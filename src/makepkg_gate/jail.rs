//! Guardian's own makepkg runs in the jail: what the jail is given, the
//! listing of a recipe's sources and the fetch and extraction of what it
//! lists.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{Dirs, SRCINFO_LIMITS, UpstreamStep};
use crate::error::{Error, IoContext};
use crate::sandbox::{self, FetchJail, Workspace};
use crate::tools;

/// The hidden recipe makepkg fetches from (`-p`, which must be beside the
/// real one), removed on drop.
struct RecipeCopy {
    path: PathBuf,
}

impl RecipeCopy {
    fn create(build_dir: &Path, recipe: &str) -> Result<Self, Error> {
        let path = build_dir.join(format!(".guardian-{}.PKGBUILD", random_name()?));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .at(&path)?;
        file.write_all(recipe.as_bytes()).at(&path)?;
        Ok(Self { path })
    }

    fn name(&self) -> OsString {
        self.path
            .file_name()
            .map(OsStr::to_os_string)
            .unwrap_or_default()
    }
}

impl Drop for RecipeCopy {
    fn drop(&mut self) {
        drop(fs::remove_file(&self.path));
    }
}

/// Whether makepkg may be given `path` to write to in the jail: not a
/// directory whose binding would bring back what the jail hides (the home,
/// the system, the temporary directory, or anything above them).
pub(super) fn is_jailable(path: &Path, home: &Path) -> bool {
    let Ok(path) = fs::canonicalize(path) else {
        return false;
    };
    let hidden = [home, Path::new("/usr"), Path::new("/etc"), &env::temp_dir()];
    !hidden.iter().any(|kept| {
        fs::canonicalize(kept)
            .unwrap_or_else(|_| kept.to_path_buf())
            .starts_with(&path)
    }) && !path.starts_with("/usr")
        && !path.starts_with("/etc")
}

/// Environment variables a download may need, passed into the jail as set.
const PASSED_VARIABLES: &[&str] = &[
    "LANG",
    "TERM",
    "XDG_CONFIG_HOME",
    "http_proxy",
    "https_proxy",
    "ftp_proxy",
    "all_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "FTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
];

/// The files of a gpg home directory that hold public keys and their trust.
const PUBLIC_KEYRING: &[&str] = &[
    "pubring.kbx",
    "pubring.gpg",
    "trustdb.gpg",
    "gpg.conf",
    "common.conf",
    "public-keys.d/pubring.db",
];

/// Copies the public part of the user's keyring into `workspace`, so
/// source signatures verify in the jail without the private keys being
/// there. `None` without a keyring.
pub(super) fn public_keyring(home: &Path, workspace: &Path) -> Option<PathBuf> {
    let source = env::var_os("GNUPGHOME").map_or_else(|| home.join(".gnupg"), PathBuf::from);
    if !source.is_dir() {
        return None;
    }
    let copy = workspace.join("gnupg");
    let private = |path: &Path| DirBuilder::new().mode(0o700).create(path);
    private(&copy).ok()?;
    private(&copy.join("public-keys.d")).ok()?;
    for name in PUBLIC_KEYRING {
        let from = source.join(name);
        if fs::metadata(&from).is_ok_and(|metadata| metadata.is_file()) {
            fs::copy(&from, copy.join(name)).ok()?;
        }
    }
    Some(copy)
}

/// One of Guardian's two makepkg runs in the jail, with the build and
/// download directories makepkg is given in it.
#[derive(Clone, Copy)]
enum Run<'a> {
    /// Listing the sources: directories inside the jail's temporary one.
    /// The recipe's own code runs here, so the jail shows it as little of
    /// Guardian as it can: `wrapper` stands where the PKGBUILD is, and the
    /// workspace is seen at `inside`, a name like any build directory's.
    List {
        dirs: &'a Dirs,
        wrapper: &'a Path,
        inside: &'a Path,
    },
    /// Fetching them: the real directories, writable.
    Fetch(&'a Dirs),
}

/// The user's home, which the jail empties.
pub(super) fn home() -> Result<PathBuf, Error> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute() && home.parent().is_some())
        .ok_or_else(|| Error::Refused("HOME is not set to a directory".into()))
}

/// Puts `extra` Bubblewrap arguments before the `--chdir <dir> --` that
/// `sandbox::fetch_jail` ends with, so they are mounted over what it binds.
pub(super) fn with_mounts(mut command: Vec<OsString>, extra: Vec<OsString>) -> Vec<OsString> {
    let at = command.len().saturating_sub(3);
    command.splice(at..at, extra);
    command
}

/// The Bubblewrap command that runs makepkg with `arguments` in the jail,
/// for one of two runs. Listing the sources sources the real recipe: no
/// network, the recipe's directory read-only, and makepkg's build and
/// download directories pointed at the jail's own temporary directory.
/// Fetching (`fetch`) runs the generated recipe: the network, a copy of
/// the public keyring, and the real directories writable. `workspace` is
/// writable in both, for the listing's report and the keyring.
fn jailed(
    step: &UpstreamStep<'_>,
    workspace: &Workspace,
    run: Run<'_>,
    arguments: &[OsString],
) -> Result<Vec<OsString>, Error> {
    let home = home()?;
    let configuration = env::var_os("XDG_CONFIG_HOME")
        .map_or_else(|| home.join(".config"), PathBuf::from)
        .join("pacman/makepkg.conf");
    let mut readable = vec![configuration, home.join(".makepkg.conf")];
    let mut writable: Vec<&Path> = Vec::new();
    let mut keyring = None;
    let mut mounts: Vec<OsString> = Vec::new();
    let (dirs, fetch) = match run {
        Run::Fetch(dirs) => {
            writable.push(workspace.path());
            for directory in [step.build_dir, &dirs.builddir, &dirs.srcdest] {
                // makepkg would create a configured one; a bind needs it.
                fs::create_dir_all(directory).at(directory)?;
                if !is_jailable(directory, &home) {
                    return Err(Error::Refused(format!(
                        "{} holds more than a build, so the sources cannot be fetched into it in the sandbox",
                        directory.display()
                    )));
                }
                if !writable.contains(&directory) {
                    writable.push(directory);
                }
            }
            keyring = public_keyring(&home, workspace.path());
            (dirs, true)
        }
        Run::List {
            dirs,
            wrapper,
            inside,
        } => {
            readable.push(step.build_dir.to_path_buf());
            mounts.extend([
                "--bind".into(),
                workspace.path().into(),
                inside.into(),
                "--ro-bind".into(),
                wrapper.into(),
                step.build_dir.join("PKGBUILD").into(),
            ]);
            (dirs, false)
        }
    };

    // The listing has no network, and what it prints becomes requests: it
    // is not told the proxies, which may hold credentials.
    let passed: Vec<(&str, OsString)> = PASSED_VARIABLES
        .iter()
        .filter(|name| fetch || !name.to_ascii_lowercase().ends_with("_proxy"))
        .filter_map(|name| Some((*name, env::var_os(name)?)))
        .collect();
    let mut environment: Vec<(&str, &OsStr)> = vec![
        ("HOME", home.as_os_str()),
        ("PATH", "/usr/bin".as_ref()),
        ("BUILDDIR", dirs.builddir.as_os_str()),
        ("SRCDEST", dirs.srcdest.as_os_str()),
    ];
    // Nothing is packaged or logged in the jail. makepkg only wants a
    // package directory it can write to: for the listing, where a user's
    // own setting could point; the others are left as makepkg finds them.
    let packages = home.join("packages");
    if fetch {
        for name in ["PKGDEST", "SRCPKGDEST", "LOGDEST"] {
            environment.push((name, "/tmp".as_ref()));
        }
    } else {
        environment.push(("PKGDEST", packages.as_os_str()));
    }
    environment.extend(
        passed
            .iter()
            .map(|(name, value)| (*name, value.as_os_str())),
    );

    let command = sandbox::fetch_jail(&FetchJail {
        home: &home,
        readable: &readable,
        writable: &writable,
        keyring: keyring.as_deref(),
        network: fetch,
        environment: &environment,
        directory: step.build_dir,
    });
    let mut command = with_mounts(command, mounts);
    command.push(step.makepkg.into());
    command.extend(arguments.iter().cloned());
    Ok(command)
}

/// The recipe the listing runs in place of the real one: it loads the real
/// one, a copy at `real`, and then writes the two directories as that left
/// them to `report`. It runs in the shell the recipe ran in, so it shows
/// what a recipe did in passing (however it was written), not what one
/// written to deceive it wants hidden. What the recipe prints while it
/// loads goes to standard error: the listing is read from standard output,
/// which makepkg alone should write.
pub(super) fn listing_recipe(real: &Path, report: &Path) -> String {
    let quoted = |path: &Path| format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"));
    format!(
        "source {} >&2\nprintf '%s\\0%s\\0' \"$BUILDDIR\" \"$SRCDEST\" >{}\n",
        quoted(real),
        quoted(report)
    )
}

/// The most a listing's report can hold: two paths.
const MAX_REPORT_BYTES: u64 = 16 * 1024;

/// What the listing run reported, if it left a plain file of a sane size:
/// the recipe's shell wrote it, so it may be anything.
pub(super) fn listing_report(path: &Path) -> Option<Vec<u8>> {
    fs::symlink_metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file() && metadata.len() <= MAX_REPORT_BYTES)
        .and_then(|_| fs::read(path).ok())
}

/// Eight random bytes as text, for a name no recipe can know beforehand.
fn random_name() -> Result<String, Error> {
    let mut bytes = [0_u8; 8];
    fs::File::open("/dev/urandom")
        .and_then(|mut random| io::Read::read_exact(&mut random, &mut bytes))
        .at(Path::new("/dev/urandom"))?;
    Ok(bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    }))
}

/// Has makepkg list the recipe's sources (`--printsrcinfo`), in the jail:
/// the recipe's top-level code runs there, with no network and nothing of
/// the user's to read or write. Its build and download directories are
/// pointed at names made up for this run, inside the jail's own temporary
/// directory. Returns the listing, unless the recipe did not leave those
/// two as they were: it would move the real build's too.
///
/// The jail is made to look like an ordinary run as far as that is cheap:
/// makepkg is called as a user calls it, on a file named `PKGBUILD` in the
/// recipe's directory, with no variable of Guardian's in the environment.
/// A recipe that looks can still tell: there is no network, its directory
/// is read-only, the home is empty, and the file it is loaded from is a
/// copy in the temporary directory.
pub(super) fn probe(step: &UpstreamStep<'_>) -> Result<String, Error> {
    let workspace = Workspace::create("probe")?;
    // The name is random, so no recipe can assign these by rote.
    let inside = Path::new("/tmp").join(format!("makepkg-{}", random_name()?));
    let write = |name: &str, text: &str| -> Result<PathBuf, Error> {
        let path = workspace.path().join(name);
        fs::write(&path, text).at(&path)?;
        Ok(path)
    };
    write("PKGBUILD", step.recipe)?;
    let wrapper = write(
        "wrapper",
        &listing_recipe(&inside.join("PKGBUILD"), &inside.join("report")),
    )?;
    let listing = Dirs {
        builddir: inside.join("build"),
        srcdest: inside.join("sources"),
        pkgbase: String::new(),
        startdir: step.build_dir.to_path_buf(),
    };
    let mut args: Vec<OsString> = vec!["--printsrcinfo".into()];
    args.extend(step.mirrored.iter().cloned());
    let run = Run::List {
        dirs: &listing,
        wrapper: &wrapper,
        inside: &inside,
    };
    let command = jailed(step, &workspace, run, &args)?;
    let captured = tools::run_in(
        Path::new(tools::BWRAP),
        &command,
        step.build_dir,
        &[],
        SRCINFO_LIMITS,
    )?
    .into_success()?;
    let mut expected = listing.builddir.as_os_str().as_encoded_bytes().to_vec();
    expected.push(0);
    expected.extend(listing.srcdest.as_os_str().as_encoded_bytes());
    expected.push(0);
    match listing_report(&workspace.path().join("report")) {
        Some(report) if report == expected => Ok(String::from_utf8_lossy(&captured).into_owned()),
        Some(_) => Err(Error::Refused(
            "the PKGBUILD moves makepkg's build or download directory".into(),
        )),
        None => Err(Error::Refused(
            "the PKGBUILD did not finish loading here (it stops or fails on this system)".into(),
        )),
    }
}

/// Fetches and extracts the sources, in the jail with the network on, from
/// `recipe`: the generated one, so none of the package's recipe runs. A
/// source tree left by an earlier run is removed first (`--cleanbuild`).
pub(super) fn pre_extract(
    step: &UpstreamStep<'_>,
    dirs: &Dirs,
    recipe: &str,
) -> Result<(), String> {
    let prepare = |error: Error| format!("could not prepare the sources ({error}).");
    let workspace = Workspace::create("fetch").map_err(prepare)?;
    let copy = RecipeCopy::create(step.build_dir, recipe).map_err(prepare)?;
    let mut args: Vec<OsString> = vec!["-p".into(), copy.name()];
    args.extend(
        [
            "--nobuild",
            "--noprepare",
            "--nodeps",
            "--noconfirm",
            "--cleanbuild",
        ]
        .map(Into::into),
    );
    args.extend(step.mirrored.iter().cloned());
    let command = jailed(step, &workspace, Run::Fetch(dirs), &args).map_err(prepare)?;
    errln!(
        "Guardian: fetching and extracting the sources for review, in a sandbox (makepkg downloads what the PKGBUILD lists; the PKGBUILD itself does not run and nothing is built)..."
    );
    let status = Command::new(tools::BWRAP)
        .current_dir(step.build_dir)
        .args(command)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| format!("could not run makepkg to fetch the sources ({error})."))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "fetching the sources for review failed ({status})."
        ))
    }
}
