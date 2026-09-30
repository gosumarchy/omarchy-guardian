//! Running a command against a disposable, verified copy of reviewed source
//! inside Bubblewrap.

use std::env;
use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, IoContext};
use crate::scan::{self, ScanConfig, Snapshot};
use crate::tools;

const MAX_COPY_SIZE: u64 = 512 * 1024 * 1024;
const TIMEOUT: &str = "120s";

/// A private temporary directory removed on drop.
pub struct Workspace {
    path: PathBuf,
}

impl Workspace {
    pub fn create(label: &str) -> Result<Self, Error> {
        // The counter keeps workspaces created at once by parallel reviews apart.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let path = env::temp_dir().join(format!(
            "omarchy-guardian-{label}-{}-{nonce}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        // Created with its final mode: no window in which it is readable by
        // others, and `create` (not `create_all`) fails if the name exists.
        DirBuilder::new().mode(0o700).create(&path).at(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        // Nothing useful can be done if cleanup fails while unwinding.
        drop(fs::remove_dir_all(&self.path));
    }
}

/// Copies the reviewed tree, proves the copy matches the reviewed snapshot,
/// and runs `command` inside it.
pub fn run(
    config: &ScanConfig,
    reviewed: &Snapshot,
    command: &[OsString],
) -> Result<ExitCode, Error> {
    let Some((program, arguments)) = command.split_first() else {
        return Err(Error::Refused("no sandbox command was given".into()));
    };

    scan::verify_unchanged(config, reviewed)?;
    let workspace = Workspace::create("sandbox")?;
    let source = workspace.path().join("source");
    let mut copied = 0;
    copy_tree(&config.root, &source, &mut copied)?;

    let mut copy_config = config.clone();
    copy_config.root.clone_from(&source);
    scan::verify_unchanged(&copy_config, reviewed).map_err(|_| {
        Error::Refused("the sandbox copy does not match the reviewed source".into())
    })?;

    outln!(
        "Sandbox: network isolated · no host home directory · read-only system · {} MiB disposable source copy",
        copied / (1024 * 1024)
    );
    let status = Command::new(tools::TIMEOUT)
        .args(["--signal=TERM", "--kill-after=5s", TIMEOUT, tools::BWRAP])
        .args(BWRAP_ARGS)
        .arg("--bind")
        .arg(&source)
        .args([
            "/workspace",
            "--chdir",
            "/workspace",
            "--setenv",
            "HOME",
            "/home/guardian",
            "--setenv",
            "XDG_CONFIG_HOME",
            "/home/guardian/.config",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--",
        ])
        .arg(program)
        .args(arguments)
        .status()
        .map_err(|source| Error::Spawn {
            tool: "bwrap".into(),
            source,
        })?;

    if status.success() {
        outln!("Sandbox run completed with exit code 0.");
    } else {
        eprintln!("Sandbox command exited with {status}.");
    }
    Ok(tools::exit_code_of(status))
}

const BWRAP_ARGS: &[&str] = &[
    "--die-with-parent",
    "--new-session",
    "--unshare-all",
    // --unshare-all only tries a user namespace; --disable-userns needs one.
    "--unshare-user",
    "--disable-userns",
    "--assert-userns-disabled",
    "--cap-drop",
    "ALL",
    "--clearenv",
    "--ro-bind",
    "/usr",
    "/usr",
    "--ro-bind",
    "/etc",
    "/etc",
    "--symlink",
    "usr/bin",
    "/bin",
    "--symlink",
    "usr/lib",
    "/lib",
    "--symlink",
    "usr/lib",
    "/lib64",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",
    "--dir",
    "/home",
    "--dir",
    "/home/guardian",
    "--dir",
    "/home/guardian/.config",
];

/// Copies regular files, directories and symbolic links (as links, never
/// followed), skipping `.git` like the review does, and refusing anything
/// else. The copy is verified against the reviewed snapshot afterwards, which
/// only accepts links that stay inside the tree.
fn copy_tree(source: &Path, destination: &Path, total: &mut u64) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(source).at(source)?;
    if !metadata.is_dir() {
        return Err(Error::Refused(format!(
            "not a non-symlink directory: {}",
            source.display()
        )));
    }
    DirBuilder::new()
        .mode(0o700)
        .create(destination)
        .at(destination)?;

    for entry in fs::read_dir(source).at(source)? {
        let entry = entry.at(source)?;
        let from = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(Error::Refused(format!(
                "non-UTF-8 path in source tree: {}",
                from.display()
            )));
        };
        if name == ".git" {
            continue;
        }

        let to = destination.join(name);
        let file_type = entry.file_type().at(&from)?;
        if file_type.is_dir() {
            copy_tree(&from, &to, total)?;
        } else if file_type.is_file() {
            *total = total.saturating_add(entry.metadata().at(&from)?.len());
            if *total > MAX_COPY_SIZE {
                return Err(Error::Refused(format!(
                    "source exceeds the sandbox copy limit of {} MiB",
                    MAX_COPY_SIZE / (1024 * 1024)
                )));
            }
            fs::copy(&from, &to).at(&from)?;
        } else if file_type.is_symlink() {
            let target = fs::read_link(&from).at(&from)?;
            symlink(&target, &to).at(&to)?;
        } else {
            return Err(Error::Refused(format!(
                "unsupported file type: {}",
                from.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    use super::{BWRAP_ARGS, Workspace, copy_tree};
    use crate::test_support::TempDir;

    #[test]
    fn user_namespace_is_unshared_before_it_is_disabled() {
        let position = |flag| BWRAP_ARGS.iter().position(|arg| *arg == flag).unwrap();
        assert!(position("--unshare-user") < position("--disable-userns"));
    }

    #[test]
    fn workspace_is_private_and_removed() {
        let path = {
            let workspace = Workspace::create("test").unwrap();
            let mode = fs::metadata(workspace.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
            workspace.path().to_path_buf()
        };
        assert!(!path.exists());
    }

    #[test]
    fn copy_omits_git_metadata_and_keeps_symlinks_as_links() {
        let root = TempDir::new("sandbox-copy");
        let source = root.path().join("source");
        fs::create_dir_all(source.join(".git")).unwrap();
        fs::write(source.join("main.rs"), "fn main() {}\n").unwrap();
        fs::write(source.join(".git/config"), "remote = private\n").unwrap();

        let mut total = 0;
        copy_tree(&source, &root.path().join("copied"), &mut total).unwrap();
        assert!(root.path().join("copied/main.rs").is_file());
        assert!(!root.path().join("copied/.git").exists());
        assert_eq!(total, "fn main() {}\n".len() as u64);

        symlink("main.rs", source.join("linked.rs")).unwrap();
        let mut total = 0;
        copy_tree(&source, &root.path().join("second"), &mut total).unwrap();
        let copied = root.path().join("second/linked.rs");
        assert!(
            fs::symlink_metadata(&copied)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&copied).unwrap(), Path::new("main.rs"));
    }
}
