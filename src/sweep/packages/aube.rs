//! The packages in aube's lockfile (`aube-lock.yaml`), which mise's
//! `npm:` backend leaves in each tool it installs with aube. aube writes
//! it in pnpm's v9 format
//! (<https://github.com/aubepkg/aube/blob/4c8884d2d60499757e703b9d1285c36bb3ebfcb1/crates/aube-lockfile/src/pnpm/write.rs>):
//! a `packages:` section with one `name@version:` key per package, at two
//! spaces, and its `resolution:` in flow style at four.
//!
//! This is not a YAML parser. It reads only that layout and fails closed:
//! a file in any other shape is not read at all, and an entry it cannot
//! read marks the file as read in part, so the caller can say so.

/// One package the lockfile names.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(super) struct Locked {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) resolution: Resolution,
}

/// Where a locked package was fetched from, by its `resolution`.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(super) enum Resolution {
    /// Only an integrity hash: from the registry aube was set to use, which
    /// the lockfile does not name.
    Registry,
    /// A registry's tarball address in its usual layout,
    /// `<registry>/<name>/-/<basename>-<version>.tgz` (written with
    /// `lockfileIncludeTarballUrl`): the address names the registry.
    Tarball(String),
    /// git, a local directory or file, another address, or a version no
    /// registry gives: the name may be private.
    Elsewhere,
}

/// What a lockfile records.
#[derive(Debug, Default)]
pub(super) struct Lock {
    pub(super) packages: Vec<Locked>,
    /// An entry under `packages:` could not be read.
    pub(super) partial: bool,
}

/// An entry under `packages:` as it is read: its key line, and its
/// `resolution` once seen.
struct Entry<'a> {
    key: &'a str,
    resolution: Option<&'a str>,
    /// More than one `resolution` line.
    repeated: bool,
}

/// The packages in the lockfile `text`, or `None` where it is not one
/// aube writes in pnpm's v9 format or names no package.
pub(super) fn read(text: &str) -> Option<Lock> {
    // A tab cannot indent YAML, and CR line ends are not what aube writes:
    // either would move where an entry starts.
    if text.contains(['\t', '\r']) {
        return None;
    }
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let version = lines.next()?.strip_prefix("lockfileVersion:")?.trim();
    if !matches!(version, "'9.0'" | "\"9.0\"" | "9.0") {
        return None;
    }
    let mut lock = Lock::default();
    let mut in_packages = false;
    let mut seen_packages = false;
    let mut entry: Option<Entry<'_>> = None;
    for line in lines {
        let indent = line.len() - line.trim_start_matches(' ').len();
        if indent == 0 {
            finish(entry.take(), &mut lock);
            // A top-level line that is not a plain `key:` (a comment, a
            // second document, a flow mapping) could hide where the
            // section ends.
            in_packages = top_level_key(line)? == "packages";
            if in_packages && seen_packages {
                return None;
            }
            seen_packages |= in_packages;
            continue;
        }
        if !in_packages {
            continue;
        }
        match indent {
            2 => {
                finish(entry.take(), &mut lock);
                entry = Some(Entry {
                    key: &line[2..],
                    resolution: None,
                    repeated: false,
                });
            }
            4 => {
                let Some(value) = line[4..].strip_prefix("resolution:") else {
                    continue;
                };
                match entry.as_mut() {
                    Some(entry) => {
                        entry.repeated |= entry.resolution.is_some();
                        entry.resolution = Some(value);
                    }
                    None => lock.partial = true,
                }
            }
            1 | 3 => lock.partial = true,
            _ => {}
        }
    }
    finish(entry, &mut lock);
    (seen_packages && !lock.packages.is_empty()).then_some(lock)
}

/// The key of a top-level line: `key:` opening a section, or `key: value`
/// (pnpm's format has top-level checksums such as `pnpmfileChecksum`).
/// `packages` takes no value but `{}`, an empty section: any other would
/// hold packages in a form not read here.
fn top_level_key(line: &str) -> Option<&str> {
    let (key, value) = if let Some(key) = line.strip_suffix(':') {
        (key, None)
    } else {
        let (key, value) = line.split_once(": ")?;
        (key, Some(value))
    };
    let plain = !key.is_empty()
        && key
            .chars()
            .all(|character| character.is_ascii_alphanumeric());
    let packages_in_another_form = key == "packages" && !matches!(value, None | Some("{}"));
    (plain && !packages_in_another_form).then_some(key)
}

/// Takes in `entry`, or marks the lock as read in part.
fn finish(entry: Option<Entry<'_>>, lock: &mut Lock) {
    let Some(entry) = entry else {
        return;
    };
    let locked = entry
        .resolution
        .filter(|_| !entry.repeated)
        .and_then(|resolution| locked(entry.key, resolution));
    match locked {
        Some(locked) => lock.packages.push(locked),
        None => lock.partial = true,
    }
}

/// The package an entry's key line (after its indent) and `resolution`
/// value name.
fn locked(key_line: &str, resolution: &str) -> Option<Locked> {
    let key = key_line.strip_suffix(':')?;
    let key = match key.strip_prefix('\'') {
        // A scoped name starts with `@`, which YAML reserves, so aube
        // quotes it. A quote inside would be written doubled; npm names
        // and versions have none.
        Some(quoted) => quoted
            .strip_suffix('\'')
            .filter(|key| !key.contains('\''))?,
        None if key.starts_with(|first: char| first.is_ascii_alphanumeric()) => key,
        None => return None,
    };
    // The version follows the last `@`; a scoped name has one at the start.
    let at = key.rfind('@').filter(|&at| at > 0)?;
    let (name, version) = (&key[..at], &key[at + 1..]);
    if !is_npm_name(name) {
        return None;
    }
    // A key whose version is an address, a path or an alias (`npm:`) is
    // what aube writes for a package from elsewhere.
    let resolution = if is_version(version) {
        resolution_of(resolution.trim(), name, version)?
    } else {
        Resolution::Elsewhere
    };
    Some(Locked {
        name: name.to_string(),
        version: version.to_string(),
        resolution,
    })
}

/// Whether `name` has the characters of an npm package name, scoped
/// (`@scope/name`) or not. Old names may have capitals.
fn is_npm_name(name: &str) -> bool {
    let part = |part: &str| {
        !part.is_empty()
            && !part.starts_with('.')
            && part
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-._~".contains(character))
    };
    match name.strip_prefix('@') {
        Some(scoped) => scoped
            .split_once('/')
            .is_some_and(|(scope, name)| part(scope) && part(name)),
        None => part(name),
    }
}

/// Whether `version` reads as a semver version: a digit first, then
/// letters, digits, `.`, `-` and `+`.
fn is_version(version: &str) -> bool {
    version.starts_with(|first: char| first.is_ascii_digit())
        && version
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-+".contains(character))
}

/// What a `resolution` flow mapping (`{integrity: ..., tarball: ...}`)
/// says of a package from a registry, or `None` where it is not one.
fn resolution_of(value: &str, name: &str, version: &str) -> Option<Resolution> {
    let inner = value.strip_prefix('{')?.strip_suffix('}')?;
    let mut integrity = false;
    let mut tarball = None;
    // An integrity hash is base64 and an address has no `, `, so the
    // fields split there.
    for field in inner.split(", ") {
        let (key, value) = field.split_once(": ")?;
        match key {
            "integrity" if !integrity && !value.is_empty() => integrity = true,
            "tarball" if tarball.is_none() => tarball = Some(unquoted(value)?),
            // Fields of git's and of a local directory's resolutions.
            "commit" | "repo" | "type" | "directory" | "gitHosted" | "path" => {
                return Some(Resolution::Elsewhere);
            }
            _ => return None,
        }
    }
    Some(match tarball {
        Some(url) if is_registry_tarball(url, name, version) => {
            Resolution::Tarball(url.to_string())
        }
        Some(_) => Resolution::Elsewhere,
        None if integrity => Resolution::Registry,
        None => return None,
    })
}

/// A plain or single-quoted YAML scalar, unquoted.
fn unquoted(value: &str) -> Option<&str> {
    match value.strip_prefix('\'') {
        Some(quoted) => quoted
            .strip_suffix('\'')
            .filter(|text| !text.contains('\'')),
        None => (!value.is_empty() && !value.starts_with('"')).then_some(value),
    }
}

/// Whether `url` is the address a registry serves `name` at `version`
/// from, so the name in the key is the one the registry knows (aube's
/// `registry_tarball_url_is_not_derivable`, in the file cited above).
fn is_registry_tarball(url: &str, name: &str, version: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or_default();
    let basename = name.rsplit('/').next().unwrap_or(name);
    path.ends_with(&format!("/{name}/-/{basename}-{version}.tgz"))
}

#[cfg(test)]
mod tests {
    use super::{Lock, Locked, Resolution, read};
    use crate::test_support::Rng;

    /// A lockfile with every kind of entry aube writes. The names are made
    /// up.
    const LOCK: &str = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

pnpmfileChecksum: sha256-abc

importers:

  .:
    dependencies:
      '@acme/tool':
        specifier: 1.2.3
        version: 1.2.3

packages:

  '@acme/tool@1.2.3':
    resolution: {integrity: sha512-AAAA+/==}
    engines: {node: '>=20'}
    hasBin: true

  plain-dep@0.4.0-beta.1:
    resolution: {integrity: sha512-BBBB==, tarball: https://registry.npmjs.org/plain-dep/-/plain-dep-0.4.0-beta.1.tgz}

  from-git@https://codeload.github.com/acme/from-git/tar.gz/abc:
    resolution: {tarball: https://codeload.github.com/acme/from-git/tar.gz/abc}
    version: 2.0.0

  local@file:vendor/local:
    resolution: {directory: vendor/local, type: directory}

  renamed@1.0.0:
    resolution: {integrity: sha512-CCCC==, tarball: https://registry.npmjs.org/other/-/other-1.0.0.tgz}

  pinned@3.0.0:
    resolution: {commit: abc, repo: https://git.example/pinned, type: git}

snapshots:

  '@acme/tool@1.2.3':
    dependencies:
      plain-dep: 0.4.0-beta.1
";

    fn names(lock: &Lock) -> Vec<(&str, &str, &Resolution)> {
        lock.packages
            .iter()
            .map(|locked| {
                (
                    locked.name.as_str(),
                    locked.version.as_str(),
                    &locked.resolution,
                )
            })
            .collect()
    }

    #[test]
    fn every_entry_is_read_with_where_it_came_from() {
        let lock = read(LOCK).unwrap();

        let tarball = "https://registry.npmjs.org/plain-dep/-/plain-dep-0.4.0-beta.1.tgz";
        assert_eq!(
            names(&lock),
            [
                ("@acme/tool", "1.2.3", &Resolution::Registry),
                (
                    "plain-dep",
                    "0.4.0-beta.1",
                    &Resolution::Tarball(tarball.into())
                ),
                (
                    "from-git",
                    "https://codeload.github.com/acme/from-git/tar.gz/abc",
                    &Resolution::Elsewhere
                ),
                ("local", "file:vendor/local", &Resolution::Elsewhere),
                ("renamed", "1.0.0", &Resolution::Elsewhere),
                ("pinned", "3.0.0", &Resolution::Elsewhere),
            ]
        );
        assert!(!lock.partial);
    }

    #[test]
    fn another_shape_is_not_read() {
        for text in [
            "",
            "packages:\n  a@1.0.0:\n    resolution: {integrity: x}\n",
            &LOCK.replace("'9.0'", "'6.0'"),
            &LOCK.replace('\n', "\r\n"),
            &LOCK.replace("    resolution", "\tresolution"),
            // A comment could hide where the section ends.
            &LOCK.replace("\n  plain-dep", "\n# note\n  plain-dep"),
            &format!("{LOCK}packages:\n  a@1.0.0:\n    resolution: {{integrity: x}}\n"),
            // No package at all.
            "lockfileVersion: '9.0'\n\npackages: {}\n",
            "lockfileVersion: '9.0'\n\nimporters:\n  .: {}\n",
            // Packages in another form than a section.
            "lockfileVersion: '9.0'\npackages: [a@1.0.0]\n",
        ] {
            assert!(read(text).is_none(), "{text:?}");
        }
    }

    #[test]
    fn an_entry_that_cannot_be_read_is_counted_and_not_taken() {
        let acme = "  '@acme/tool@1.2.3':";
        let resolution = "{integrity: sha512-AAAA+/==}";
        for (from, to) in [
            (format!("    resolution: {resolution}"), String::new()),
            (
                resolution.into(),
                "{integrity: sha512-AAAA+/==, odd: 1}".into(),
            ),
            (resolution.into(), "{}".into()),
            (resolution.into(), "integrity: sha512-AAAA+/==".into()),
            (resolution.into(), "{tarball: \"https://x\"}".into()),
            (acme.into(), "  \"@acme/tool@1.2.3\":".into()),
            (acme.into(), "  '@acme/tool':".into()),
            (acme.into(), "  '@acme/to ol@1.2.3':".into()),
            (acme.into(), "  -acme@1.2.3:".into()),
            (acme.into(), "   '@acme/tool@1.2.3':".into()),
            (
                "    hasBin: true".into(),
                "    resolution: {integrity: sha512-DDDD==}".into(),
            ),
        ] {
            let lock = read(&LOCK.replacen(&from, &to, 1)).unwrap();

            assert!(lock.partial, "{from:?} -> {to:?}");
            assert!(
                names(&lock).iter().all(|(name, ..)| *name != "@acme/tool"),
                "{from:?} -> {to:?}"
            );
        }
    }

    /// One package of a generated lockfile, as aube would write it, and
    /// what reading it must give.
    fn generated(rng: &mut Rng) -> (String, Locked) {
        let name = rng.text(&["a", "b", "z", "0", "-", ".", "_"], 6);
        let name = format!("{}{name}", rng.pick(&["n", "x"]));
        let name = if rng.chance(2) {
            format!("@{}/{name}", rng.pick(&["acme", "a.b", "s-1"]))
        } else {
            name
        };
        let version = format!(
            "{}.{}.{}{}",
            rng.below(20),
            rng.below(20),
            rng.below(20),
            rng.pick(&["", "-beta.1", "+build.5", "-rc-2"])
        );
        let basename = name.rsplit('/').next().unwrap();
        let tarball = format!("https://registry.npmjs.org/{name}/-/{basename}-{version}.tgz");
        let (resolution, expected) = match rng.below(4) {
            0 => (
                "{integrity: sha512-Zz+/9==}".to_string(),
                Resolution::Registry,
            ),
            1 => (
                format!("{{integrity: sha512-Zz==, tarball: {tarball}}}"),
                Resolution::Tarball(tarball),
            ),
            2 => (
                "{commit: c0ffee, repo: https://git.example/r, type: git}".to_string(),
                Resolution::Elsewhere,
            ),
            _ => (
                "{tarball: https://files.example/p.tgz}".to_string(),
                Resolution::Elsewhere,
            ),
        };
        let key = if name.starts_with('@') {
            format!("'{name}@{version}'")
        } else {
            format!("{name}@{version}")
        };
        let entry = format!("  {key}:\n    resolution: {resolution}\n    hasBin: true\n\n");
        let locked = Locked {
            name,
            version,
            resolution: expected,
        };
        (entry, locked)
    }

    /// Lockfiles generated as aube writes them read back as the packages
    /// they were made from.
    #[test]
    fn generated_lockfiles_read_back_as_written() {
        let mut rng = Rng::new(11);
        for _ in 0..2_000 {
            let mut text =
                "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\npackages:\n\n".to_string();
            let mut expected = Vec::new();
            for _ in 0..=rng.below(6) {
                let (entry, locked) = generated(&mut rng);
                text.push_str(&entry);
                expected.push(locked);
            }
            text.push_str("snapshots:\n\n  x@1.0.0: {}\n");

            let lock = read(&text).unwrap();

            assert_eq!(lock.packages, expected, "{text}");
            assert!(!lock.partial, "{text}");
        }
    }

    /// Text made of the pieces the format is written with, and the sample
    /// with bytes changed: reading never panics, and a package taken as
    /// from a registry has a version for a key and, for a tarball, the
    /// address of its own name.
    #[test]
    fn any_text_is_read_safely_and_takes_only_registry_keys() {
        const PIECES: &[&str] = &[
            "lockfileVersion: '9.0'\n",
            "packages:\n",
            "snapshots:\n",
            "\n",
            "  ",
            "    ",
            "'",
            "@",
            "/",
            ":",
            ": ",
            ", ",
            "{",
            "}",
            "a",
            "1.0.0",
            "resolution: ",
            "integrity: sha512-x",
            "tarball: https://registry.npmjs.org/a/-/a-1.0.0.tgz",
            "type: git",
            "#",
        ];
        let mut rng = Rng::new(7);
        for round in 0..20_000 {
            let text = if round % 2 == 0 {
                rng.text(PIECES, 40)
            } else {
                rng.mutated(LOCK, PIECES)
            };
            let Some(lock) = read(&text) else {
                continue;
            };
            assert!(!lock.packages.is_empty(), "{text:?}");
            for locked in &lock.packages {
                let key = format!("{}@{}", locked.name, locked.version);
                assert!(text.contains(&key), "{key:?} not in {text:?}");
                if locked.resolution != Resolution::Elsewhere {
                    assert!(
                        locked.version.starts_with(|c: char| c.is_ascii_digit()),
                        "{key:?} in {text:?}"
                    );
                }
                if let Resolution::Tarball(url) = &locked.resolution {
                    let own = format!("/{}/-/", locked.name);
                    assert!(url.contains(&own), "{url:?} in {text:?}");
                }
            }
        }
    }
}
