//! The directory the gate keeps its records in, and, where it has none,
//! why: each reason with what the user is told to do about it.

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use super::DIRECTORY;
use crate::error::Error;
use crate::paths::{self, NotPrivate};

/// Why the gate has no directory to keep its records in. A call that
/// extracts, or is held to what was extracted, does not go on without one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::makepkg_gate) enum Missing {
    /// No place for one is known: neither `XDG_STATE_HOME` nor `HOME`
    /// names one.
    Nowhere,
    /// Which user Guardian runs as cannot be told, and so not whether
    /// `directory` is that user's alone.
    UnknownUser { directory: PathBuf, reason: String },
    /// These, the directory or the one above it, are open to group or
    /// others.
    Open { directories: Vec<PathBuf> },
    /// `path` belongs to `owner`, not to the user (`uid`). It is the
    /// directory or the one above it, or, where `above`, the nearest that
    /// exists above `directory`, which was to be made under it.
    Owner {
        directory: PathBuf,
        path: PathBuf,
        owner: u32,
        uid: u32,
        above: bool,
    },
    /// A link, a file or something else is at `path`, where a directory
    /// goes.
    NotDirectory { path: PathBuf },
    /// `directory` could not be made, or looked at.
    NotMade { directory: PathBuf, reason: String },
}

/// The directory under the review memory's `root`, made for the user
/// (`uid`) alone where it is not there.
pub(super) fn place(root: Option<&Path>, uid: Result<u32, Error>) -> Result<PathBuf, Missing> {
    let Some(root) = root else {
        return Err(Missing::Nowhere);
    };
    let directory = root.join(DIRECTORY);
    let uid = uid.map_err(|error| Missing::UnknownUser {
        directory: directory.clone(),
        reason: error.to_string(),
    })?;
    paths::check_private_dir(root, uid)
        .map_err(|refusal| Missing::of(root, uid, refusal, Some(&directory)))?;
    match DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            let path = directory.clone();
            return Err(Missing::NotMade {
                reason: Error::Io { path, source }.to_string(),
                directory,
            });
        }
    }
    paths::check_private_dir(&directory, uid)
        .map_err(|refusal| Missing::of(&directory, uid, refusal, None))?;
    Ok(directory)
}

/// Whether a directory open to group or others is at `path`.
fn is_open(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|found| found.is_dir() && found.mode() & 0o077 != 0)
}

impl Missing {
    /// Why `checked` was refused. `below` is the directory under it that
    /// is looked at too where `checked` is open to others, so that both
    /// are named at once.
    fn of(checked: &Path, uid: u32, refusal: NotPrivate, below: Option<&Path>) -> Self {
        match refusal {
            NotPrivate::Open { path } => {
                let mut directories = vec![path];
                directories.extend(below.filter(|below| is_open(below)).map(Path::to_path_buf));
                Self::Open { directories }
            }
            NotPrivate::Owner { path, owner, above } => Self::Owner {
                directory: checked.to_path_buf(),
                path,
                owner,
                uid,
                above,
            },
            NotPrivate::NotDirectory { path, .. } => Self::NotDirectory { path },
            NotPrivate::Other(error) => Self::NotMade {
                directory: checked.to_path_buf(),
                reason: error.to_string(),
            },
        }
    }

    /// Why, in a few words, for where it is said in passing.
    pub(super) fn reason(&self) -> String {
        match self {
            Self::Nowhere => "neither XDG_STATE_HOME nor HOME names a place to keep it".into(),
            Self::UnknownUser { reason, .. } | Self::NotMade { reason, .. } => reason.clone(),
            Self::Open { directories } => format!(
                "{} {} accessible to group or others",
                listed(directories, " and "),
                if directories.len() == 1 { "is" } else { "are" }
            ),
            Self::Owner {
                path, owner, uid, ..
            } => format!("{} is owned by uid {owner}, not {uid}", path.display()),
            Self::NotDirectory { path } => format!("{} is not a directory", path.display()),
        }
    }

    /// What is noted of a build stopped for it.
    pub(in crate::makepkg_gate) fn why(&self) -> &'static str {
        match self {
            Self::Nowhere => "Guardian has nowhere to keep its records of builds",
            Self::UnknownUser { .. } => "Guardian cannot tell which user it runs as",
            Self::Open { .. } => "the directory of Guardian's records of builds is open to others",
            Self::Owner { above: false, .. } => {
                "the directory of Guardian's records of builds belongs to another user"
            }
            Self::Owner { above: true, .. } => {
                "a directory above Guardian's records of builds belongs to another user"
            }
            Self::NotDirectory { .. } => {
                "something that is not a directory is in the place of Guardian's records of builds"
            }
            Self::NotMade { .. } => {
                "the directory of Guardian's records of builds could not be made"
            }
        }
    }

    /// What a build stopped for it is told: what is wrong, what that
    /// means for the call (one that `extracts`, or one held to what was
    /// extracted), and the repair that fits.
    pub(in crate::makepkg_gate) fn message(&self, extracts: bool) -> String {
        let lost = if extracts {
            "no record of the sources it extracted for this build could be kept, and a later call of this build could not be held to them"
        } else {
            "whether it has a record of the sources it extracted for this build cannot be known, and the sources cannot be held against one"
        };
        let (wrong, repair) = self.wrong_and_repair();
        format!(
            "{wrong}, so {lost}. Nothing was built. {repair} Then run the build again from the start."
        )
    }

    fn wrong_and_repair(&self) -> (String, String) {
        const ELSEWHERE: &str = "point XDG_STATE_HOME at a directory on a filesystem that can";
        let unused = |reason: String| {
            format!(
                "Guardian does not use the directory it keeps its records of builds in ({reason})"
            )
        };
        match self {
            Self::Nowhere => (
                "Guardian has nowhere to keep its records of builds (neither XDG_STATE_HOME nor HOME names a place)".into(),
                "Set HOME, or XDG_STATE_HOME, to a directory of yours.".into(),
            ),
            Self::UnknownUser { directory, reason } => (
                format!(
                    "Guardian cannot tell which user it runs as ({reason}), and so not whether the directory it keeps its records of builds in ({}) is that user's alone",
                    directory.display()
                ),
                "It reads that from /proc/self/status: run the build where /proc is mounted and can be read.".into(),
            ),
            Self::Open { directories } => (
                unused(self.reason()),
                format!(
                    "Closing it is not enough: while it was open, someone else may have put records in it, and Guardian would take them for its own. Close it and drop what it holds (`chmod 700 {}`, then `omarchy-guardian forget --all`, which drops all of Guardian's review memory), or remove it (`rm -r {}`; Guardian makes it anew). Where the filesystem cannot keep such a mode, {ELSEWHERE}.",
                    listed(directories, " "),
                    directories.first().map(|first| first.display().to_string()).unwrap_or_default()
                ),
            ),
            Self::Owner { path, owner, uid, above: false, .. } => (
                unused(format!("{} is owned by uid {owner}, not by you, uid {uid}", path.display())),
                format!(
                    "Whoever owns it may have put records in it, and Guardian would take them for its own. Remove it (`sudo rm -r {0}`; Guardian makes it anew), or make it yours and drop what it holds (`sudo chown -R {uid} {0}`, then `omarchy-guardian forget --all`, which drops all of Guardian's review memory). Where the filesystem cannot keep an owner, {ELSEWHERE}.",
                    path.display()
                ),
            ),
            Self::Owner { directory, path, owner, uid, above: true } => (
                format!(
                    "Guardian does not make the directory it keeps its records of builds in ({}): {}, the nearest directory above it that exists, is owned by uid {owner}, not by you, uid {uid}",
                    directory.display(),
                    path.display()
                ),
                // No command for it: the directory above may be `/`, or a
                // home that is not this user's, and neither is to be given
                // away.
                format!(
                    "Have its owner make {} for you (a directory of yours alone, mode 700), or point XDG_STATE_HOME at a directory of yours.",
                    directory.display()
                ),
            ),
            Self::NotDirectory { path } => (
                unused(format!(
                    "{} is not a directory: a link, a file or something else is in its place",
                    path.display()
                )),
                format!(
                    "Remove what is in its place (`rm {}`, which removes a link and not what it points to); Guardian makes the directory anew.",
                    path.display()
                ),
            ),
            Self::NotMade { directory, reason } => (
                format!("Guardian could not make the directory it keeps its records of builds in ({reason})"),
                format!(
                    "Free space on that disk, or put right what the error names, so that {} can be made.",
                    directory.display()
                ),
            ),
        }
    }
}

fn listed(paths: &[PathBuf], between: &str) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(between)
}
