//! Which archive files a transaction installs: the ones named on the command
//! line, and for a sync the ones the databases list, found in a package
//! cache nobody else can write to.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::argv::is_valid_package_name;
use super::{C_LOCALE, TOOL_LIMITS};
use crate::classify;
use crate::config::Settings;
use crate::config::model::SourceClass;
use crate::error::{Error, IoContext};
use crate::tools;
use crate::user;

const DEFAULT_CACHE_DIR: &str = "/var/cache/pacman/pkg/";
/// Per-target archive lookup result: the archives, or why none was usable.
pub(super) type Archives = HashMap<String, Result<Vec<PathBuf>, String>>;

/// For `-U`: every operand is a package archive, whatever its name (pacman
/// reads the file, not its extension), resolved against pacman's working
/// directory and grouped by the package it holds. One left out would have
/// its target looked up in the sync databases and reviewed as another file.
pub(super) fn local_archives(operands: &[String], cwd: &Path) -> Result<Archives, Error> {
    let mut archives: Archives = HashMap::new();

    for argument in operands {
        // pacman reads `-` as "archives named on standard input".
        if argument == "-" {
            return Err(Error::Refused(
                "package archives named on standard input are not supported; name them as arguments"
                    .into(),
            ));
        }
        if argument.contains("://") {
            return Err(Error::Refused(format!(
                "remote package URLs are not supported: {argument}"
            )));
        }

        let path = cwd.join(argument);
        let metadata = match fs::symlink_metadata(&path) {
            Err(error)
                if error.kind() == io::ErrorKind::NotFound && Path::new(argument).is_relative() =>
            {
                return Err(Error::Refused(format!(
                    "cannot find {argument} relative to pacman's working directory ({}); run pacman -U with an absolute path",
                    cwd.display()
                )));
            }
            other => other.at(&path)?,
        };
        if !metadata.is_file() {
            return Err(Error::Refused(format!(
                "not a regular package archive: {}",
                path.display()
            )));
        }
        check_private(&path, user::real_uid())?;

        let name = package_name(&path)?;
        if let Ok(paths) = archives.entry(name).or_insert_with(|| Ok(Vec::new())) {
            paths.push(path);
        }
    }

    if archives.is_empty() {
        return Err(Error::Refused(
            "the upgrade did not name a readable package archive".into(),
        ));
    }
    Ok(archives)
}

/// Transaction targets that no archive on the command line provides.
pub(super) fn missing_targets(targets: &[String], archives: &Archives) -> Vec<String> {
    targets
        .iter()
        .filter(|target| !archives.contains_key(*target))
        .cloned()
        .collect()
}

/// One repository's offer of a package: the version pacman would install and
/// the repository offering it, which decides the package's source class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SyncCandidate {
    pub(super) version: String,
    pub(super) version_arch: String,
    pub(super) repo: String,
}

/// For `-S`: the archive of each target's sync-database version in pacman's
/// cache directories, read once and indexed by file name, plus each target's
/// source class as decided by the repository offering it.
pub(super) fn sync_archives(
    targets: &[String],
    settings: &Settings,
) -> Result<(Archives, HashMap<String, SourceClass>), Error> {
    let versions = sync_versions(targets)?;
    let cache = cache_index(&cache_directories()?)?;
    let filenames = sync_filenames(&versions)?;
    let mut archives = Archives::new();

    for target in targets {
        let Some(candidates) = versions.get(target) else {
            archives.insert(
                target.clone(),
                Err("pacman has no sync database entry for it".into()),
            );
            continue;
        };

        // The archive pacman installs is the one its database names, not
        // one that merely looks like the package's name and version.
        let mut found = Vec::new();
        let mut unknown = None;
        for candidate in candidates {
            let key = (
                candidate.repo.clone(),
                target.clone(),
                candidate.version.clone(),
            );
            match filenames.get(&key) {
                Some(name) => {
                    if let Some(path) = cache.get(name) {
                        found.push(path.clone());
                    }
                }
                // Which file this repository would install is not known:
                // another repository's archive must not stand in for it.
                None => unknown = Some(candidate.repo.clone()),
            }
        }
        if let Some(repo) = unknown {
            archives.insert(
                target.clone(),
                Err(format!(
                    "pacman did not say which file the repository {repo:?} installs for it"
                )),
            );
            continue;
        }
        for path in &found {
            let name = package_name(path)?;
            if name != *target {
                return Err(Error::Refused(format!(
                    "{} contains {name}, not {target}",
                    path.display()
                )));
            }
        }

        let entry = if found.is_empty() {
            Err("no archive of the version being installed is in the pacman cache".into())
        } else {
            Ok(found)
        };
        archives.insert(target.clone(), entry);
    }

    let official_repos = settings.official_repos();
    // Every candidate repo's SigLevel is queried at most once per
    // transaction, since `pacman-conf` is one process invocation.
    let mut siglevels: HashMap<String, bool> = HashMap::new();
    let mut classes = HashMap::new();
    for (target, candidates) in &versions {
        let mut candidate_classes = Vec::new();
        for candidate in candidates {
            let required = if let Some(required) = siglevels.get(&candidate.repo) {
                *required
            } else {
                let required = classify::requires_signatures(&classify::siglevel(&candidate.repo)?);
                siglevels.insert(candidate.repo.clone(), required);
                required
            };
            candidate_classes.push(classify::repo_class(
                &candidate.repo,
                &official_repos,
                required,
            ));
        }
        classes.insert(target.clone(), classify::strictest(candidate_classes));
    }

    Ok((archives, classes))
}

/// (repository, package, version) to the archive's file name.
type Filenames = HashMap<(String, String, String), String>;

/// Separates the fields pacman prints for a package: no name, version or
/// file name holds it.
const FIELD: char = '\u{1f}';

/// The file name pacman itself gives each candidate's archive, asked of
/// pacman (`-Sp --print-format`) one repository at a time, so it is read
/// from the sync database exactly as the transaction reads it. `-dd`
/// keeps it to the packages named; printing takes no database lock, which
/// the running transaction holds. A repository pacman cannot answer for
/// has no file names, and its targets then have no archive.
pub(super) fn sync_filenames(
    versions: &HashMap<String, Vec<SyncCandidate>>,
) -> Result<Filenames, Error> {
    let mut wanted: HashMap<&str, Vec<&str>> = HashMap::new();
    for (name, candidates) in versions {
        for candidate in candidates {
            wanted
                .entry(candidate.repo.as_str())
                .or_default()
                .push(name);
        }
    }
    let mut filenames = Filenames::new();
    for (repo, names) in wanted {
        if !is_valid_package_name(repo) {
            continue;
        }
        let mut args: Vec<OsString> = vec![
            "-Sp".into(),
            "-dd".into(),
            "--print-format".into(),
            format!("%r{FIELD}%n{FIELD}%v{FIELD}%f").into(),
            "--".into(),
        ];
        args.extend(
            names
                .iter()
                .map(|name| OsString::from(format!("{repo}/{name}"))),
        );
        let captured = tools::run(Path::new(tools::PACMAN), &args, None, C_LOCALE, TOOL_LIMITS)?;
        if !captured.status.success() {
            continue;
        }
        filenames.extend(parse_filenames(&String::from_utf8_lossy(&captured.stdout)));
    }
    Ok(filenames)
}

/// The packages `pacman -Sp` printed in `sync_filenames`' format. A file
/// name that is not a plain one is left out.
pub(super) fn parse_filenames(output: &str) -> Filenames {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(4, FIELD);
            let key = (
                fields.next()?.to_string(),
                fields.next()?.to_string(),
                fields.next()?.to_string(),
            );
            let filename = fields.next()?;
            let plain =
                !filename.is_empty() && !filename.contains('/') && !filename.starts_with('.');
            plain.then(|| (key, filename.to_string()))
        })
        .collect()
}

/// `name → [candidate, ...]` from `pacman -Si`. A package present in several
/// repositories yields several candidates.
pub(super) fn sync_versions(
    targets: &[String],
) -> Result<HashMap<String, Vec<SyncCandidate>>, Error> {
    let mut args: Vec<OsString> = vec!["-Si".into(), "--".into()];
    args.extend(targets.iter().map(OsString::from));
    // Unknown targets make pacman exit non-zero while still printing the
    // others; those targets are then reported individually.
    let captured = tools::run(Path::new(tools::PACMAN), &args, None, C_LOCALE, TOOL_LIMITS)?;
    Ok(parse_sync_info(&String::from_utf8_lossy(&captured.stdout)))
}

pub(super) fn parse_sync_info(output: &str) -> HashMap<String, Vec<SyncCandidate>> {
    let mut versions: HashMap<String, Vec<SyncCandidate>> = HashMap::new();
    let mut fields: HashMap<&str, &str> = HashMap::new();

    let mut flush = |fields: &mut HashMap<&str, &str>| {
        if let (Some(name), Some(version), Some(arch), Some(repo)) = (
            fields.get("Name"),
            fields.get("Version"),
            fields.get("Architecture"),
            fields.get("Repository"),
        ) {
            versions
                .entry((*name).to_string())
                .or_default()
                .push(SyncCandidate {
                    version: (*version).to_string(),
                    version_arch: format!("{version}-{arch}"),
                    repo: (*repo).to_string(),
                });
        }
        fields.clear();
    };

    for line in output.lines() {
        if line.trim().is_empty() {
            flush(&mut fields);
        } else if let Some((key, value)) = line.split_once(':')
            && !line.starts_with(' ')
        {
            fields.insert(key.trim(), value.trim());
        }
    }
    flush(&mut fields);
    versions
}

/// The archive and every directory above it may only be changed by root or
/// the invoking user: pacman opens the path again after the review, so
/// another user who could swap it would install unreviewed code.
pub(super) fn check_private(path: &Path, uid: Option<u32>) -> Result<(), Error> {
    let mut current = Some(path);
    while let Some(here) = current {
        let metadata = fs::symlink_metadata(here).at(here)?;
        let sticky = metadata.is_dir() && metadata.mode() & 0o1000 != 0;
        let foreign_owner = user::is_foreign_owner(metadata.uid(), uid);
        let shared = metadata.mode() & 0o022 != 0 && !sticky;
        if foreign_owner || shared {
            return Err(Error::Refused(format!(
                "{} can be changed by another user ({}), so the archive pacman installs may not be the one reviewed; move it to a directory only you can write",
                path.display(),
                here.display()
            )));
        }
        current = here.parent();
    }
    Ok(())
}

/// A cache directory must be root's alone: `-S` packages are reviewed there
/// after pacman verified them, and installed from there.
fn check_cache_directory(directory: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).at(directory),
        Ok(metadata) if metadata.uid() == 0 && metadata.mode() & 0o022 == 0 => Ok(()),
        Ok(_) => Err(Error::Refused(format!(
            "the pacman cache directory {} is not root's alone",
            directory.display()
        ))),
    }
}

fn cache_directories() -> Result<Vec<PathBuf>, Error> {
    let output = tools::run(
        Path::new(tools::PACMAN_CONF),
        &["CacheDir".into()],
        None,
        C_LOCALE,
        TOOL_LIMITS,
    )?
    .into_success()?;
    let directories: Vec<PathBuf> = String::from_utf8_lossy(&output)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect();
    if directories.is_empty() {
        Ok(vec![PathBuf::from(DEFAULT_CACHE_DIR)])
    } else {
        Ok(directories)
    }
}

/// Regular files in the cache directories by name. Symlinks are ignored.
fn cache_index(directories: &[PathBuf]) -> Result<HashMap<String, PathBuf>, Error> {
    let mut index = HashMap::new();
    for directory in directories {
        check_cache_directory(directory)?;
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).at(directory),
        };
        for entry in entries {
            let entry = entry.at(directory)?;
            let is_file = entry.file_type().at(directory)?.is_file();
            if let (true, Ok(name)) = (is_file, entry.file_name().into_string()) {
                index.entry(name).or_insert_with(|| entry.path());
            }
        }
    }
    Ok(index)
}

fn package_name(archive: &Path) -> Result<String, Error> {
    let output = tools::run(
        Path::new(tools::PACMAN),
        &["-Qqp".into(), "--".into(), archive.into()],
        None,
        C_LOCALE,
        TOOL_LIMITS,
    )?
    .into_success()?;
    let name = String::from_utf8_lossy(&output).trim().to_string();
    if is_valid_package_name(&name) {
        Ok(name)
    } else {
        Err(Error::Refused(format!(
            "pacman reported an invalid package name for {}",
            archive.display()
        )))
    }
}
