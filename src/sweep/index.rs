//! Which installed package owns a path, and what pacman recorded for it.
//!
//! Read from pacman's local database (`/var/lib/pacman/local/<pkg>-<ver>/`):
//! `desc` names the package and `mtree` (gzip) lists every file it installed
//! with its mode, SHA-256 and link target. A file that still matches its
//! record is what its package shipped.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::Path;

use crate::error::Error;
use crate::payload::unescape;
use crate::sha256::Digest;
use crate::tools::{self, Limits};

pub const LOCAL_DB: &str = "/var/lib/pacman/local";
const GZIP: &str = "/usr/bin/gzip";
const PACMAN: &str = "/usr/bin/pacman";

/// The largest `mtree` read for one package once decompressed, and for all
/// of them together.
const MAX_MTREE: usize = 32 * 1024 * 1024;
const MAX_TOTAL: usize = 256 * 1024 * 1024;

/// What pacman recorded for one installed path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recorded {
    File {
        /// Permission bits, including set-id bits (`0o4755`).
        mode: u32,
        sha256: Option<Digest>,
    },
    Link(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owned {
    /// Index into `PackageIndex::packages`.
    package: usize,
    pub recorded: Recorded,
    /// A configuration file the package expects the administrator to edit
    /// (`backup=` in its PKGBUILD).
    pub backup: bool,
}

#[derive(Debug, Default)]
pub struct PackageIndex {
    packages: Vec<String>,
    owners: HashMap<String, Owned>,
    foreign: HashSet<String>,
    /// The first repository-package file with each content, for files
    /// copied out of a package (Omarchy's `etc-overrides`).
    copies: HashMap<Digest, String>,
    /// Packages whose record could not be read.
    pub problems: Vec<String>,
}

impl PackageIndex {
    /// Reads every package under `db`. `foreign` names packages from no
    /// configured repository (AUR, `pacman -U`).
    pub fn load(db: &Path, foreign: HashSet<String>) -> Result<Self, Error> {
        let mut index = Self {
            foreign,
            ..Self::default()
        };
        let mut directories: Vec<_> = fs::read_dir(db)
            .map_err(|source| Error::Io {
                path: db.to_path_buf(),
                source,
            })?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect();
        directories.sort();

        let mut total = 0;
        for directory in directories {
            let shown = directory.display().to_string();
            let Some(name) = fs::read_to_string(directory.join("desc"))
                .ok()
                .and_then(|desc| package_name(&desc))
            else {
                index.problems.push(format!("{shown}: no package name"));
                continue;
            };
            match read_mtree(&directory.join("mtree")) {
                Ok(text) => {
                    total += text.len();
                    if total > MAX_TOTAL {
                        index
                            .problems
                            .push("package records exceed the size limit".into());
                        break;
                    }
                    let backup = fs::read_to_string(directory.join("files"))
                        .map(|files| backup_paths(&files))
                        .unwrap_or_default();
                    index.add(&name, &text, &backup);
                }
                Err(error) => index.problems.push(format!("{name}: {error}")),
            }
        }
        Ok(index)
    }

    /// Records `package`'s files from its decompressed `mtree`; `backup`
    /// lists its configuration files. A path another package already owns
    /// keeps its first owner.
    fn add(&mut self, package: &str, mtree: &str, backup: &HashSet<String>) {
        let number = self.packages.len();
        self.packages.push(package.to_string());
        let repository = !self.is_foreign(package);
        for (path, recorded) in parse_mtree(mtree) {
            if let Recorded::File {
                sha256: Some(digest),
                ..
            } = &recorded
                && repository
                && !backup.contains(&path)
            {
                self.copies.entry(*digest).or_insert_with(|| path.clone());
            }
            let backup = backup.contains(&path);
            self.owners.entry(path).or_insert(Owned {
                package: number,
                recorded,
                backup,
            });
        }
    }

    /// The repository-package file whose content is `digest`, if any.
    pub fn copy_of(&self, digest: &Digest) -> Option<&str> {
        self.copies.get(digest).map(String::as_str)
    }

    /// The record for `path`, relative to `/` (`usr/bin/ssh`).
    pub fn owner(&self, path: &str) -> Option<&Owned> {
        self.owners.get(path)
    }

    pub fn package(&self, owned: &Owned) -> &str {
        &self.packages[owned.package]
    }

    /// Whether `package` comes from no configured repository.
    pub fn is_foreign(&self, package: &str) -> bool {
        self.foreign.contains(package)
    }

    pub fn len(&self) -> usize {
        self.owners.len()
    }

    #[cfg(test)]
    pub fn with_foreign(foreign: HashSet<String>) -> Self {
        Self {
            foreign,
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub fn add_for_test(&mut self, package: &str, mtree: &str, backup: &[&str]) {
        let backup = backup.iter().map(|path| (*path).to_string()).collect();
        self.add(package, mtree, &backup);
    }
}

/// The `%BACKUP%` paths of a package's `files` record (`path<TAB>md5`).
fn backup_paths(files: &str) -> HashSet<String> {
    files
        .lines()
        .skip_while(|line| *line != "%BACKUP%")
        .skip(1)
        .take_while(|line| !line.is_empty() && !line.starts_with('%'))
        .filter_map(|line| line.split('\t').next())
        .map(str::to_string)
        .collect()
}

/// `%NAME%` from a package's `desc`.
fn package_name(desc: &str) -> Option<String> {
    let mut lines = desc.lines();
    lines.find(|line| *line == "%NAME%")?;
    lines
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn read_mtree(path: &Path) -> Result<String, Error> {
    let captured = tools::run(
        Path::new(GZIP),
        &[OsString::from("-dc"), path.as_os_str().to_os_string()],
        None,
        &[],
        Limits {
            timeout_secs: 30,
            max_output: MAX_MTREE,
        },
    )?;
    let bytes = captured.into_success()?;
    String::from_utf8(bytes).map_err(|_| Error::Refused(format!("{}: not UTF-8", path.display())))
}

/// The packages from no configured repository (`pacman -Qmq`). pacman exits
/// 1 when there are none.
pub fn foreign_packages() -> Result<HashSet<String>, Error> {
    let captured = tools::run(
        Path::new(PACMAN),
        &[OsString::from("-Qmq")],
        None,
        &[("LC_ALL", "C")],
        Limits {
            timeout_secs: 60,
            max_output: 4 * 1024 * 1024,
        },
    )?;
    if captured.status.success() || (captured.stdout.is_empty() && captured.stderr.is_empty()) {
        Ok(parse_names(&captured.stdout))
    } else {
        captured.into_success().map(|_| HashSet::new())
    }
}

fn parse_names(stdout: &[u8]) -> HashSet<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

/// The regular files and links an `mtree` lists, by path relative to `/`.
/// Directories and the package's own metadata (`.PKGINFO`, `.BUILDINFO`…)
/// are left out, as are names that do not unescape cleanly.
fn parse_mtree(text: &str) -> Vec<(String, Recorded)> {
    let mut defaults: HashMap<&str, &str> = HashMap::new();
    let mut entries = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let Some(first) = words.next() else {
            continue;
        };
        if first.starts_with('#') {
            continue;
        }
        if first == "/set" {
            for (key, value) in words.filter_map(|word| word.split_once('=')) {
                defaults.insert(key, value);
            }
            continue;
        }
        if first == "/unset" {
            for key in words {
                defaults.remove(key);
            }
            continue;
        }
        let Some(path) = first.strip_prefix("./").and_then(unescape) else {
            continue;
        };
        if path.starts_with('.') || path.is_empty() {
            continue;
        }
        let mut fields = defaults.clone();
        for (key, value) in words.filter_map(|word| word.split_once('=')) {
            fields.insert(key, value);
        }
        let recorded = match fields.get("type").copied().unwrap_or("file") {
            "file" => Recorded::File {
                mode: fields
                    .get("mode")
                    .and_then(|mode| u32::from_str_radix(mode, 8).ok())
                    .unwrap_or(0),
                sha256: fields
                    .get("sha256digest")
                    .and_then(|hex| Digest::from_hex(hex)),
            },
            "link" => match fields.get("link").and_then(|target| unescape(target)) {
                Some(target) => Recorded::Link(target),
                None => continue,
            },
            _ => continue,
        };
        entries.push((path, recorded));
    }
    entries
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use super::{
        LOCAL_DB, PackageIndex, Recorded, backup_paths, foreign_packages, package_name,
        parse_mtree, parse_names,
    };
    use crate::sha256::Sha256;
    use crate::test_support::{TempDir, tool_available};

    const MTREE: &str = "#mtree
/set type=file uid=0 gid=0 mode=644
./.BUILDINFO time=1.0 size=10 sha256digest=00
./.PKGINFO time=1.0 size=10 sha256digest=00
./usr time=1.0 mode=755 type=dir
./usr/bin time=1.0 mode=755 type=dir
./usr/bin/demo time=1.0 mode=755 size=3 sha256digest=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
./usr/bin/su time=1.0 mode=4755 size=3 sha256digest=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
./usr/lib/libdemo.so time=1.0 mode=777 type=link link=libdemo.so.1
./usr/share/demo/with\\040space time=1.0 size=0 sha256digest=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
/set mode=600
./etc/demo.conf time=1.0 size=0
";

    #[test]
    fn mtree_records_files_and_links_with_their_modes() {
        let entries = parse_mtree(MTREE);
        let paths: Vec<&str> = entries.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "usr/bin/demo",
                "usr/bin/su",
                "usr/lib/libdemo.so",
                "usr/share/demo/with space",
                "etc/demo.conf"
            ]
        );
        assert_eq!(
            entries[1].1,
            Recorded::File {
                mode: 0o4755,
                sha256: Some(Sha256::digest(b"abc"))
            }
        );
        assert_eq!(entries[2].1, Recorded::Link("libdemo.so.1".into()));
        assert_eq!(
            entries[4].1,
            Recorded::File {
                mode: 0o600,
                sha256: None
            }
        );
    }

    #[test]
    fn backup_files_come_from_the_files_record() {
        assert_eq!(
            backup_paths("%FILES%\netc/\netc/a.conf\n\n%BACKUP%\netc/a.conf\tabc\netc/b\tdef\n"),
            HashSet::from(["etc/a.conf".to_string(), "etc/b".to_string()])
        );
        assert!(backup_paths("%FILES%\netc/a\n").is_empty());
    }

    #[test]
    fn names_come_from_desc_and_pacman() {
        assert_eq!(
            package_name("%NAME%\nopenssh\n\n%VERSION%\n10.5p1-1\n").as_deref(),
            Some("openssh")
        );
        assert_eq!(package_name("%VERSION%\n1\n"), None);
        assert_eq!(
            parse_names(b"yay-bin\nomarchy-guardian\n"),
            HashSet::from(["yay-bin".to_string(), "omarchy-guardian".to_string()])
        );
    }

    fn write_package(db: &Path, name: &str, mtree: &str) {
        let directory = db.join(format!("{name}-1-1"));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("desc"), format!("%NAME%\n{name}\n")).unwrap();
        fs::write(directory.join("mtree.txt"), mtree).unwrap();
        let status = Command::new("/usr/bin/gzip")
            .args(["-n", "-c"])
            .arg(directory.join("mtree.txt"))
            .stdout(fs::File::create(directory.join("mtree")).unwrap())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn this_systems_database_is_read_when_there_is_one() {
        if !Path::new(LOCAL_DB).is_dir() || !tool_available("/usr/bin/gzip") {
            return;
        }
        let foreign = foreign_packages().unwrap();
        let index = PackageIndex::load(Path::new(LOCAL_DB), foreign).unwrap();
        let pacman = index.owner("usr/bin/pacman").unwrap();
        assert_eq!(index.package(pacman), "pacman");
        assert!(matches!(
            pacman.recorded,
            Recorded::File {
                sha256: Some(_),
                ..
            }
        ));
        assert!(index.problems.is_empty(), "{:?}", index.problems);
    }

    #[test]
    fn the_index_reads_a_local_database() {
        if !tool_available("/usr/bin/gzip") {
            return;
        }
        let db = TempDir::new("pacman-local");
        write_package(db.path(), "demo", MTREE);
        write_package(
            db.path(),
            "other",
            "#mtree\n./usr/bin/demo time=1.0 mode=755 size=1 sha256digest=00\n./usr/bin/other time=1.0 mode=755\n",
        );
        fs::create_dir(db.path().join("broken-1-1")).unwrap();

        let index = PackageIndex::load(db.path(), HashSet::from(["other".to_string()])).unwrap();
        let demo = index.owner("usr/bin/demo").unwrap();
        assert_eq!(index.package(demo), "demo");
        assert_eq!(
            index.package(index.owner("usr/bin/other").unwrap()),
            "other"
        );
        assert!(index.owner("usr/bin/missing").is_none());
        assert!(index.is_foreign("other") && !index.is_foreign("demo"));
        assert_eq!(index.len(), 6);
        assert_eq!(index.problems.len(), 1, "{:?}", index.problems);
    }
}
