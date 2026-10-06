//! Where Guardian keeps things: the XDG base directories, and directories
//! that only one user can reach. Also the parts of a path written as text.

use std::env;
use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

/// Which values of an environment variable are taken as a directory.
#[derive(Clone, Copy)]
pub(crate) enum Accept {
    /// Whatever it holds, a relative or an empty path too.
    Any,
    /// Only an absolute path; anything else is as if it were not set.
    Absolute,
}

/// `$XDG_STATE_HOME`, else `~/.local/state`.
pub(crate) fn state_home(xdg: Accept, home: Accept) -> Option<PathBuf> {
    base("XDG_STATE_HOME", xdg, home, ".local/state")
}

/// `$XDG_CONFIG_HOME`, else `~/.config`.
pub(crate) fn config_home(xdg: Accept, home: Accept) -> Option<PathBuf> {
    base("XDG_CONFIG_HOME", xdg, home, ".config")
}

/// `$XDG_CACHE_HOME`, else `~/.cache`.
pub(crate) fn cache_home(xdg: Accept, home: Accept) -> Option<PathBuf> {
    base("XDG_CACHE_HOME", xdg, home, ".cache")
}

fn base(variable: &str, xdg: Accept, home: Accept, below_home: &str) -> Option<PathBuf> {
    resolve(
        (env::var_os(variable), xdg),
        (env::var_os("HOME"), home),
        below_home,
    )
}

/// The XDG directory where it is set and accepted, else `below_home` under
/// the home directory where that is.
fn resolve(
    (xdg, accept_xdg): (Option<OsString>, Accept),
    (home, accept_home): (Option<OsString>, Accept),
    below_home: &str,
) -> Option<PathBuf> {
    let accepted = |value: Option<OsString>, accept: Accept| {
        value.map(PathBuf::from).filter(|path| match accept {
            Accept::Any => true,
            Accept::Absolute => path.is_absolute(),
        })
    };
    accepted(xdg, accept_xdg)
        .or_else(|| accepted(home, accept_home).map(|home| home.join(below_home)))
}

/// The file name of a path written with `/`: what follows the last one, or
/// all of it where there is none. Nothing, for a path that ends in one.
pub(crate) fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The extension of a path's file name in lowercase: what follows its last
/// `.`, or nothing where it has none. A name that starts with its only dot
/// (`.bashrc`) has the rest as its extension.
pub(crate) fn extension_lowercase(path: &str) -> String {
    file_name(path)
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default()
}

/// Makes sure `root` is a private directory of `uid`: creates it (and
/// missing parents, mode 0700) only under an existing directory owned by
/// `uid`, then requires a real directory (not a symlink) owned by `uid` with
/// no access for group or others.
pub(crate) fn private_dir(root: &Path, uid: u32) -> Result<(), String> {
    let describe = |path: &Path, error: io::Error| format!("{}: {error}", path.display());
    match fs::symlink_metadata(root) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_root(root, uid)?,
        Err(error) => return Err(describe(root, error)),
    }

    let metadata = fs::symlink_metadata(root).map_err(|error| describe(root, error))?;
    if !metadata.file_type().is_dir() {
        return Err(format!("{} is not a directory", root.display()));
    }
    if metadata.uid() != uid {
        return Err(format!(
            "{} is owned by uid {}, not {uid}",
            root.display(),
            metadata.uid()
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(format!(
            "{} is accessible to group or others",
            root.display()
        ));
    }
    Ok(())
}

/// Creates the store directory and any missing parents (mode 0700), but only
/// when the nearest existing ancestor is a directory (a symlink to one, such
/// as a symlinked HOME, counts as its target) owned by `uid`. Under `sudo -E`
/// (euid 0, the user's HOME kept) that ancestor belongs to the user, so
/// nothing root-owned is created there. The store root itself is still
/// checked without following symlinks by `Store::open`.
fn create_root(root: &Path, uid: u32) -> Result<(), String> {
    let ancestor = nearest_existing_ancestor(root)?;
    let metadata =
        fs::metadata(&ancestor).map_err(|error| format!("{}: {error}", ancestor.display()))?;
    if !metadata.is_dir() {
        return Err(format!(
            "{} is not a directory; not creating the store under it",
            ancestor.display()
        ));
    }
    if metadata.uid() != uid {
        return Err(format!(
            "{} is owned by uid {}, not {uid}; not creating the store under it",
            ancestor.display(),
            metadata.uid()
        ));
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)
        .map_err(|error| format!("{}: {error}", root.display()))
}

/// The closest ancestor of `root` that exists (as seen by `symlink_metadata`).
fn nearest_existing_ancestor(root: &Path) -> Result<PathBuf, String> {
    for ancestor in root
        .ancestors()
        .skip(1)
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
    {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => return Ok(ancestor.to_path_buf()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", ancestor.display())),
        }
    }
    Err(format!("{} has no existing ancestor", root.display()))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::{Accept, extension_lowercase, file_name, private_dir, resolve};
    use crate::test_support::TempDir;

    fn found(
        xdg: Option<&str>,
        accept_xdg: Accept,
        home: Option<&str>,
        accept_home: Accept,
    ) -> Option<PathBuf> {
        resolve(
            (xdg.map(OsString::from), accept_xdg),
            (home.map(OsString::from), accept_home),
            ".local/state",
        )
    }

    #[test]
    fn the_xdg_directory_comes_before_the_one_under_home() {
        use Accept::{Absolute, Any};
        let path = |text: &str| Some(PathBuf::from(text));
        for (xdg, home) in [(Any, Any), (Absolute, Any), (Absolute, Absolute)] {
            assert_eq!(found(Some("/x"), xdg, Some("/h"), home), path("/x"));
            assert_eq!(found(Some("/x"), xdg, None, home), path("/x"));
            assert_eq!(found(None, xdg, Some("/h"), home), path("/h/.local/state"));
            assert_eq!(found(None, xdg, None, home), None);
        }
    }

    #[test]
    fn a_relative_directory_is_taken_only_where_any_is_accepted() {
        use Accept::{Absolute, Any};
        let path = |text: &str| Some(PathBuf::from(text));
        // The XDG variable.
        assert_eq!(found(Some("rel"), Any, Some("/h"), Any), path("rel"));
        assert_eq!(found(Some(""), Any, Some("/h"), Any), path(""));
        assert_eq!(
            found(Some("rel"), Absolute, Some("/h"), Any),
            path("/h/.local/state")
        );
        assert_eq!(
            found(Some(""), Absolute, Some("/h"), Absolute),
            path("/h/.local/state")
        );
        // HOME.
        assert_eq!(
            found(None, Absolute, Some("rel"), Any),
            path("rel/.local/state")
        );
        assert_eq!(
            found(Some("rel"), Absolute, Some("rel"), Any),
            path("rel/.local/state")
        );
        assert_eq!(found(None, Absolute, Some("rel"), Absolute), None);
        assert_eq!(found(Some("rel"), Absolute, Some("rel"), Absolute), None);
        // A component at a time or all at once, the path below home is the same.
        assert_eq!(
            found(None, Any, Some("/h"), Any),
            Some(PathBuf::from("/h").join(".local").join("state"))
        );
    }

    #[test]
    fn the_file_name_is_what_follows_the_last_slash() {
        assert_eq!(file_name("a/b/c.txt"), "c.txt");
        assert_eq!(file_name("c.txt"), "c.txt");
        assert_eq!(file_name("/usr/bin/sh"), "sh");
        assert_eq!(file_name("a/b/"), "");
        assert_eq!(file_name("/"), "");
        assert_eq!(file_name(""), "");
        assert_eq!(file_name("a//b"), "b");
        // Only `/` parts a path; nothing is resolved.
        assert_eq!(file_name("a/.."), "..");
        assert_eq!(file_name("a\\b"), "a\\b");
        // As the expression it replaces, for any of these.
        for path in [
            "",
            "/",
            "a",
            "a/",
            "/a",
            "a/b",
            "a/b/",
            "a//",
            "\u{e9}/\u{e9}",
        ] {
            assert_eq!(file_name(path), path.rsplit('/').next().unwrap_or_default());
        }
    }

    #[test]
    fn the_extension_is_what_follows_the_last_dot_of_the_name() {
        assert_eq!(extension_lowercase("a/b/c.TXT"), "txt");
        assert_eq!(extension_lowercase("archive.tar.GZ"), "gz");
        assert_eq!(extension_lowercase("a.d/file"), "");
        assert_eq!(extension_lowercase("file"), "");
        assert_eq!(extension_lowercase("file."), "");
        assert_eq!(extension_lowercase(".bashrc"), "bashrc");
        assert_eq!(extension_lowercase("a/.SH"), "sh");
        assert_eq!(extension_lowercase("a.sh/"), "");
        assert_eq!(extension_lowercase(""), "");
    }

    #[test]
    fn a_private_directory_must_be_a_real_own_directory_closed_to_others() {
        let dir = TempDir::new("private-dir");
        let uid = std::os::unix::fs::MetadataExt::uid(&fs::metadata(dir.path()).unwrap());
        let made = dir.path().join("a/b");
        private_dir(&made, uid).unwrap();
        assert_eq!(
            fs::metadata(&made).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(private_dir(&made, uid + 1).is_err());

        let open = dir.path().join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_dir(&open, uid).is_err());

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&made, &link).unwrap();
        assert!(private_dir(&link, uid).is_err());
    }
}
