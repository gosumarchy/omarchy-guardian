//! Reading the archive's listings into the model: escaped names, the tar and
//! pax headers that carry capabilities and access control lists, and what an
//! entry's mode and owner grant.

use std::collections::{HashMap, HashSet};
use std::fs::Metadata;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;

use super::{Entry, Kind, METADATA};

/// Undoes bsdtar's (and mtree's) escaping of names (`\\`, `\n`, `\t` and
/// octal `\ooo`); `None` for a name that is not UTF-8 or holds control
/// characters.
pub fn unescape(raw: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut input = raw.bytes().peekable();
    while let Some(byte) = input.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        let escaped = match input.next()? {
            b'\\' => b'\\',
            b'n' => b'\n',
            b't' => b'\t',
            b'r' => b'\r',
            b'a' => 7,
            b'b' => 8,
            b'f' => 12,
            b'v' => 11,
            digit @ b'0'..=b'7' => {
                let mut value = u32::from(digit - b'0');
                for _ in 0..2 {
                    let next = input.next().filter(u8::is_ascii_digit)?;
                    value = value * 8 + u32::from(next - b'0');
                }
                u8::try_from(value).ok()?
            }
            _ => return None,
        };
        bytes.push(escaped);
    }
    let text = String::from_utf8(bytes).ok()?;
    (!text.chars().any(char::is_control)).then_some(text)
}

/// What a listed mode (`-rwsr-xr-x`) with its numeric owner and group
/// grants beyond an ordinary root-owned file: set-id bits, for root or for
/// anyone else.
pub(super) fn root_set_id(mode: &str, owner: &str, group: &str) -> Option<&'static str> {
    let set = |position: usize| matches!(mode.as_bytes().get(position), Some(b's' | b'S'));
    match (set(3), set(6)) {
        (true, _) if owner == "0" => Some(SETUID_ROOT),
        (_, true) if group == "0" => Some(SETGID_ROOT),
        (true, _) => Some(SETUID_OTHER),
        (_, true) => Some(SETGID_OTHER),
        _ => None,
    }
}

pub const SETUID_ROOT: &str = "setuid root";
pub const SETGID_ROOT: &str = "setgid root";
/// It runs as its owner, or with its group (`disk`, `shadow`, `kmem` reach
/// far), for whoever starts it.
pub const SETUID_OTHER: &str = "setuid for a user other than root";
pub const SETGID_OTHER: &str = "setgid for a group other than root";
/// What to call an entry that carries file capabilities, and one with an
/// access control list.
pub const WITH_CAPABILITIES: &str = "with file capabilities";
pub const WITH_ACL: &str = "with an access control list";
/// What to call a file or directory anyone may write, where the system's
/// own files are, and one that is somebody else's to write.
pub const WRITABLE_BY_ALL: &str = "writable by everyone";
pub const OWNED_BY_OTHER: &str = "owned by a user other than root";
pub const WRITABLE_BY_GROUP: &str = "writable by a group other than root";

/// Whether a listed entry under `/usr`, `/etc` or `/opt` can be written by
/// someone other than root: by everyone, by its owner, or by its group.
/// Whoever writes a file there decides what the next one to run or read it
/// gets; whoever writes a directory decides what is in it (a drop-in for a
/// root service, say).
pub(super) fn open_to_others(
    mode: &str,
    owner: &str,
    group: &str,
    path: &str,
) -> Option<&'static str> {
    if !["usr/", "etc/", "opt/"]
        .iter()
        .any(|system| path.starts_with(system))
    {
        return None;
    }
    let bytes = mode.as_bytes();
    if bytes.get(8) == Some(&b'w') && !matches!(bytes.get(9), Some(b't' | b'T')) {
        Some(WRITABLE_BY_ALL)
    } else if owner != "0" {
        Some(OWNED_BY_OTHER)
    } else if bytes.get(5) == Some(&b'w') && group != "0" {
        Some(WRITABLE_BY_GROUP)
    } else {
        None
    }
}

/// Whether what `what` names is how the installed file already is: then a
/// package that ships it that way again grants nothing new. Capabilities
/// and access lists are not read back, so those are said every time.
pub fn already_granted(what: &str, installed: &Metadata) -> bool {
    let mode = installed.mode();
    let (uid, gid) = (installed.uid(), installed.gid());
    match what {
        SETUID_ROOT => installed.is_file() && mode & 0o4000 != 0 && uid == 0,
        SETGID_ROOT => installed.is_file() && mode & 0o2000 != 0 && gid == 0,
        SETUID_OTHER => installed.is_file() && mode & 0o4000 != 0 && uid != 0,
        SETGID_OTHER => installed.is_file() && mode & 0o2000 != 0 && gid != 0,
        WRITABLE_BY_ALL => !installed.file_type().is_symlink() && mode & 0o002 != 0,
        OWNED_BY_OTHER => !installed.file_type().is_symlink() && uid != 0,
        WRITABLE_BY_GROUP => !installed.file_type().is_symlink() && mode & 0o020 != 0 && gid != 0,
        _ => false,
    }
}

/// The entries of an uncompressed pax tar stream whose extended header
/// carries a `security.*` or `trusted.*` attribute (file capabilities:
/// root-like rights for whoever runs the file) or an access control list
/// (rights the mode does not show), with what to call them.
pub(super) fn attributes_in_tar(mut stream: impl Read) -> Result<Vec<Attribute>, String> {
    let mut found = Vec::new();
    // What the extended header before the next entry said.
    let mut pending: Option<(&'static str, Option<String>)> = None;
    let mut path_override: Option<String> = None;
    let mut header = [0_u8; 512];
    loop {
        if let Err(error) = stream.read_exact(&mut header) {
            return if error.kind() == io::ErrorKind::UnexpectedEof {
                Ok(found)
            } else {
                Err(error.to_string())
            };
        }
        if header.iter().all(|byte| *byte == 0) {
            continue;
        }
        // Up to the first NUL, and otherwise as written: a name may end
        // in a blank.
        let field = |range: std::ops::Range<usize>| {
            let bytes = &header[range];
            let end = bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        };
        let size = u64::from_str_radix(field(124..136).trim(), 8)
            .map_err(|_| "an entry size that is not a number".to_string())?;
        let blocks = size.div_ceil(512) * 512;
        // A pax extended header for the next entry (`x`) or for all that
        // follow (`g`).
        let kind = header[156];
        if matches!(kind, b'x' | b'g') {
            if size > 1 << 20 {
                return Err("an extended header larger than 1 MiB".into());
            }
            let mut data = vec![0_u8; usize::try_from(blocks).map_err(|_| "size")?];
            stream
                .read_exact(&mut data)
                .map_err(|error| error.to_string())?;
            data.truncate(usize::try_from(size).map_err(|_| "size")?);
            let records = pax_records(&data);
            if kind == b'x' {
                path_override = records.path;
            }
            if let Some(what) = records.what {
                pending = Some((what, records.capability));
            }
            continue;
        }
        let name = path_override.take().unwrap_or_else(|| {
            let (prefix, name) = (field(345..500), field(0..100));
            if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            }
        });
        if let Some((what, capability)) = pending.take() {
            found.push((name.trim_end_matches('/').to_string(), what, capability));
        }
        let mut left = blocks;
        let mut sink = [0_u8; 8192];
        while left > 0 {
            let take = usize::try_from(left.min(8192)).unwrap_or(8192);
            stream
                .read_exact(&mut sink[..take])
                .map_err(|error| error.to_string())?;
            left -= take as u64;
        }
    }
}

/// From a pax extended header's records (`<length> <key>=<value>\n`): what
/// its attributes grant, if anything, and the entry's path if it gives one.
fn pax_records(data: &[u8]) -> Records {
    let mut found = Records::default();
    // Another `security.*` or `trusted.*` attribute beside the capability:
    // then the capability's value alone does not say what is granted.
    let mut others = false;
    let mut rest = data;
    while let Some(space) = rest.iter().position(|byte| *byte == b' ') {
        let Some(length) = std::str::from_utf8(&rest[..space])
            .ok()
            .and_then(|digits| digits.parse::<usize>().ok())
            .filter(|length| *length > space + 1 && *length <= rest.len())
        else {
            break;
        };
        let record = &rest[space + 1..length];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if let Some(equals) = record.iter().position(|byte| *byte == b'=') {
            let key = String::from_utf8_lossy(&record[..equals]);
            let value = &record[equals + 1..];
            if key == "path" || key == "GNU.sparse.name" {
                found.path = Some(String::from_utf8_lossy(value).into_owned());
            } else if key.contains(".xattr.security.") || key.contains(".xattr.trusted.") {
                found.what = Some(WITH_CAPABILITIES);
                // bsdtar writes each attribute twice; the `LIBARCHIVE`
                // record holds its value as base64.
                if key == "LIBARCHIVE.xattr.security.capability" {
                    found.capability = Some(String::from_utf8_lossy(value).into_owned());
                } else if key != "SCHILY.xattr.security.capability" {
                    others = true;
                }
            } else if (key.contains(".acl.") || key.contains(".xattr.system.posix_acl"))
                && found.what.is_none()
            {
                found.what = Some(WITH_ACL);
            }
        }
        rest = &rest[length..];
    }
    if others {
        found.capability = None;
    }
    found
}

/// What a pax extended header says about the entry after it.
#[derive(Default)]
struct Records {
    /// What its attributes grant, if anything.
    what: Option<&'static str>,
    /// The entry's path, if the header gives one.
    path: Option<String>,
    /// The value of its `security.capability` attribute as base64, when
    /// that is its only attribute of the kind.
    capability: Option<String>,
}

/// An entry's path, what its attributes grant, and the value of its file
/// capabilities (see `Records::capability`).
pub(super) type Attribute = (String, &'static str, Option<String>);

/// An entry under a symbolic-link directory is installed wherever that
/// link points, not where it is listed: such an archive is refused.
fn under_links(entries: &[Entry]) -> Result<(), String> {
    let links: HashSet<&str> = entries
        .iter()
        .filter(|entry| matches!(entry.kind, Kind::Symlink(_)))
        .map(|entry| entry.path.as_str())
        .collect();
    for entry in entries {
        let mut prefix = entry.path.as_str();
        while let Some((parent, _)) = prefix.rsplit_once('/') {
            if links.contains(parent) {
                return Err(format!(
                    "{} is inside {parent}, which is a symbolic link",
                    entry.path
                ));
            }
            prefix = parent;
        }
    }
    Ok(())
}

/// Builds the archive model from `bsdtar -tf` (names) and `bsdtar -tv
/// --numeric-owner` (details) output, refusing anything a real package
/// never contains.
pub(super) fn parse_model(names: &str, details: &str) -> Result<Vec<Entry>, String> {
    let names: Vec<&str> = names.lines().collect();
    let details: Vec<&str> = details.lines().collect();
    if names.len() != details.len() {
        return Err("the archive's two listings disagree".into());
    }
    let mut entries: Vec<Entry> = Vec::with_capacity(names.len());
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (raw_name, line) in names.iter().zip(&details) {
        let mut rest = *line;
        let mut fields = Vec::with_capacity(8);
        for _ in 0..8 {
            rest = rest.trim_start();
            let end = rest
                .find(char::is_whitespace)
                .ok_or_else(|| format!("unreadable listing line {line:?}"))?;
            fields.push(&rest[..end]);
            rest = &rest[end..];
        }
        let after = rest
            .strip_prefix(' ')
            .and_then(|rest| rest.strip_prefix(*raw_name))
            .ok_or_else(|| format!("unreadable listing line {line:?}"))?;
        let size: u64 = fields[4]
            .parse()
            .map_err(|_| format!("unreadable size in {line:?}"))?;
        let bad = || format!("an entry name Guardian refuses: {raw_name:?}");
        let mut path = unescape(raw_name).ok_or_else(bad)?;
        let kind = match (fields[0].chars().next(), after) {
            (Some('-'), "") => Kind::File,
            (Some('d'), "") => {
                if let Some(trimmed) = path.strip_suffix('/') {
                    path = trimmed.to_string();
                }
                Kind::Directory
            }
            (Some('l'), rest) => Kind::Symlink(
                rest.strip_prefix(" -> ")
                    .and_then(unescape)
                    .ok_or_else(bad)?,
            ),
            (Some('h'), rest) => Kind::HardLink(
                rest.strip_prefix(" link to ")
                    .and_then(unescape)
                    .ok_or_else(bad)?,
            ),
            _ => return Err(format!("an entry of a type Guardian refuses: {line:?}")),
        };
        if path.is_empty()
            || path.starts_with('/')
            || path
                .split('/')
                .any(|component| matches!(component, "" | "." | ".."))
        {
            return Err(bad());
        }
        let top = path.split('/').next().unwrap_or_default();
        if top.starts_with('.') {
            if !METADATA.contains(&path.as_str()) {
                return Err(bad());
            }
            if kind != Kind::File {
                return Err(format!("{path} is not a regular file"));
            }
        }
        if let Kind::HardLink(target) = &kind {
            let regular = seen
                .get(target)
                .is_some_and(|index| entries[*index].kind == Kind::File);
            if !regular {
                return Err(format!(
                    "{path} is a hard link to {target}, which is not an earlier regular file"
                ));
            }
        }
        if seen.insert(path.clone(), entries.len()).is_some() {
            return Err(format!("{path} appears more than once"));
        }
        let root_set_id = match kind {
            Kind::File | Kind::HardLink(_) => root_set_id(fields[0], fields[2], fields[3])
                .or_else(|| open_to_others(fields[0], fields[2], fields[3], &path)),
            Kind::Directory => open_to_others(fields[0], fields[2], fields[3], &path),
            Kind::Symlink(_) => None,
        };
        entries.push(Entry {
            path,
            size,
            kind,
            root_set_id,
        });
    }
    under_links(&entries)?;
    Ok(entries)
}
