//! Running external tools with absolute paths, a hard timeout and bounded
//! output.
//!
//! Every helper is invoked by absolute path: a gate that trusted `PATH` could
//! be disarmed by any user-level process that drops a fake `curl` or `bsdtar`
//! earlier in it.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::thread;

use crate::error::{Error, IoContext};
use crate::notify;

pub const TIMEOUT: &str = "/usr/bin/timeout";
pub const KILL: &str = "/usr/bin/kill";
pub const BSDTAR: &str = "/usr/bin/bsdtar";
pub const CURL: &str = "/usr/bin/curl";
pub const PACMAN: &str = "/usr/bin/pacman";
pub const PACMAN_CONF: &str = "/usr/bin/pacman-conf";
pub const BWRAP: &str = "/usr/bin/bwrap";

/// Locations accepted for OpenCode when the review gates a root action.
const SYSTEM_OPENCODE: &[&str] = &["/usr/bin/opencode", "/usr/local/bin/opencode"];
/// Locations accepted for the Claude Code CLI when the review gates a root
/// action.
const SYSTEM_CLAUDE: &[&str] = &["/usr/bin/claude", "/usr/local/bin/claude"];

/// The CLI that runs a review: OpenCode, or the Claude Code CLI for models
/// written `claude-code/<model>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reviewer {
    OpenCode,
    ClaudeCode,
}

impl Reviewer {
    /// The model prefix that selects the Claude Code CLI.
    pub const CLAUDE_CODE_PREFIX: &'static str = "claude-code/";

    pub fn for_model(model: Option<&str>) -> Self {
        if model.is_some_and(|model| model.starts_with(Self::CLAUDE_CODE_PREFIX)) {
            Self::ClaudeCode
        } else {
            Self::OpenCode
        }
    }

    const fn program(self) -> &'static str {
        match self {
            Self::OpenCode => "opencode",
            Self::ClaudeCode => "claude",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::OpenCode => "OpenCode",
            Self::ClaudeCode => "the Claude Code CLI",
        }
    }

    const fn system_paths(self) -> &'static [&'static str] {
        match self {
            Self::OpenCode => SYSTEM_OPENCODE,
            Self::ClaudeCode => SYSTEM_CLAUDE,
        }
    }
}

const MAX_STDERR: usize = 64 * 1024;

/// Where the OpenCode reviewer may be loaded from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenCode {
    /// The first `opencode` in an absolute `PATH` entry of the invoking user.
    UserPath,
    /// Only a root-owned binary in a system directory, for gates in front of
    /// root actions such as a pacman transaction.
    SystemOnly,
    /// An exact binary, so tests never reach a real provider.
    #[cfg(test)]
    At(PathBuf),
}

impl OpenCode {
    pub fn resolve(&self) -> Result<PathBuf, Error> {
        self.resolve_reviewer(Reviewer::OpenCode)
    }

    /// The reviewer CLI's binary under this policy.
    pub fn resolve_reviewer(&self, reviewer: Reviewer) -> Result<PathBuf, Error> {
        match self {
            Self::UserPath => {
                let path = env::var_os("PATH").unwrap_or_default();
                let found = find_in_path(reviewer.program(), &path).ok_or_else(|| {
                    Error::Refused(format!(
                        "{} (`{}`) was not found on PATH",
                        reviewer.label(),
                        reviewer.program()
                    ))
                })?;
                let scratch = scratch_directories(
                    env::var_os("HOME").as_deref(),
                    env::var_os("XDG_CACHE_HOME").as_deref(),
                );
                refuse_planted(&found, &scratch, notify::current_uid()).map_err(|reason| {
                    Error::Refused(format!(
                        "{} at {} is not used: {reason}; anything running as another user, or anything that writes a cache or temporary file, could have put it there. Install it in a directory only you or root can write, or fix PATH",
                        reviewer.label(),
                        found.display()
                    ))
                })?;
                Ok(found)
            }
            Self::SystemOnly => {
                let paths = reviewer.system_paths();
                let candidate = paths
                    .iter()
                    .map(Path::new)
                    .find(|path| path.is_file())
                    .ok_or_else(|| {
                        Error::Refused(format!(
                            "the pacman gate requires a root-owned {} at {}",
                            reviewer.label(),
                            paths.join(" or ")
                        ))
                    })?;
                let resolved = fs::canonicalize(candidate).at(candidate)?;
                verify_root_owned(&resolved)?;
                Ok(resolved)
            }
            #[cfg(test)]
            Self::At(path) => Ok(path.clone()),
        }
    }
}

/// Finds an executable in the absolute entries of a `PATH` value. Relative
/// and empty entries are skipped because they resolve against the current
/// directory, which may be the untrusted tree under review.
pub fn find_in_path(name: &str, path: &OsStr) -> Option<PathBuf> {
    env::split_paths(path)
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(name))
        .find(|candidate| {
            fs::metadata(candidate).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
}

/// Where temporary and cached files go: no place for the program that
/// judges what may be installed. `home` and `cache` are `$HOME` and
/// `$XDG_CACHE_HOME`.
fn scratch_directories(home: Option<&OsStr>, cache: Option<&OsStr>) -> Vec<PathBuf> {
    let mut directories: Vec<PathBuf> = ["/tmp", "/var/tmp", "/dev/shm"]
        .into_iter()
        .map(PathBuf::from)
        .collect();
    directories.extend(
        home.filter(|home| !home.is_empty())
            .map(|home| Path::new(home).join(".cache")),
    );
    directories.extend(
        cache
            .filter(|cache| Path::new(cache).is_absolute())
            .map(PathBuf::from),
    );
    directories
}

/// Why a reviewer found on `PATH` at `found` is not trusted to be the one
/// the user `uid` installed: it, or a directory above it, belongs to
/// someone other than that user or root, or can be written by group or
/// others, or it lies under one of the `scratch` directories. Both the
/// place `PATH` names and the place a link there leads to are checked, up
/// to the root: whoever can write a directory can replace what is in it.
///
/// A sticky directory above the one the file is in may be writable by
/// others (a shared `/srv` laid out like `/tmp`): only an entry's owner
/// renames it there, and the entry's owner is checked.
fn refuse_planted(found: &Path, scratch: &[PathBuf], uid: Option<u32>) -> Result<(), String> {
    let resolved =
        fs::canonicalize(found).map_err(|error| format!("it cannot be resolved ({error})"))?;
    for path in [found, resolved.as_path()] {
        if let Some(directory) = scratch.iter().find(|directory| path.starts_with(directory)) {
            return Err(format!(
                "{} is under {}, a temporary or cache directory",
                path.display(),
                directory.display()
            ));
        }
        for (depth, entry) in path.ancestors().enumerate() {
            let what = if depth == 0 {
                "the file"
            } else {
                "the directory"
            };
            let unread = |error| format!("{} cannot be read ({error})", entry.display());
            // A link is its owner's to point elsewhere, so both the link
            // and what it leads to are looked at.
            let link = fs::symlink_metadata(entry).map_err(unread)?;
            let metadata = fs::metadata(entry).map_err(unread)?;
            if let Some(owner) = [link.uid(), metadata.uid()]
                .into_iter()
                .find(|owner| is_foreign_owner(*owner, uid))
            {
                return Err(format!(
                    "{what} {} belongs to another user (uid {owner})",
                    entry.display()
                ));
            }
            let sticky = depth > 1 && metadata.mode() & 0o1000 != 0;
            if metadata.mode() & 0o022 != 0 && !sticky {
                return Err(format!(
                    "{what} {} is writable by other users",
                    entry.display()
                ));
            }
        }
    }
    Ok(())
}

/// Whether a file owned by `owner` belongs to someone other than root or
/// the user `uid`. In a user namespace that does not map root, root's
/// files show the overflow owner, which is then not foreign either.
pub fn is_foreign_owner(owner: u32, uid: Option<u32>) -> bool {
    owner != 0 && Some(owner) != uid && !(owner == overflow_uid() && root_unmapped())
}

/// The owner the kernel shows for users a user namespace does not map.
fn overflow_uid() -> u32 {
    fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(65_534)
}

/// Whether this process runs in a user namespace that does not map root
/// (a sandbox, as in the end-to-end tests), where root's directories show
/// the overflow owner. The real pacman hook never runs in one.
fn root_unmapped() -> bool {
    fs::read_to_string("/proc/self/uid_map").is_ok_and(|map| {
        !map.lines().any(|line| {
            let mut fields = line.split_whitespace();
            let inside: Option<u64> = fields.next().and_then(|field| field.parse().ok());
            let count: Option<u64> = fields.nth(1).and_then(|field| field.parse().ok());
            matches!((inside, count), (Some(start), Some(count)) if start == 0 && count > 0)
        })
    })
}

/// Requires `path` and every directory above it to be owned by root and not
/// writable by group or others.
fn verify_root_owned(path: &Path) -> Result<(), Error> {
    for ancestor in path.ancestors() {
        let metadata = fs::metadata(ancestor).at(ancestor)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(Error::Refused(format!(
                "{} must be owned by root and not writable by other users",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub timeout_secs: u32,
    pub max_output: usize,
}

pub struct Captured {
    tool: String,
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Captured {
    /// Stdout of a successful run, or an error that carries stderr.
    pub fn into_success(self) -> Result<Vec<u8>, Error> {
        if self.status.success() {
            return Ok(self.stdout);
        }
        Err(Error::ToolFailed {
            detail: self.failure_detail(),
            tool: self.tool,
        })
    }

    pub fn failure_detail(&self) -> String {
        // GNU timeout exits 124 when it had to stop the command.
        if self.status.code() == Some(124) {
            return "timed out".to_string();
        }
        let stderr = String::from_utf8_lossy(&self.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            format!("exited with {}", self.status)
        } else {
            stderr.chars().take(500).collect()
        }
    }
}

/// Runs `program` under `timeout`, feeding `input` on stdin and capturing at
/// most `limits.max_output` bytes of stdout. Stdin, stdout and stderr are
/// serviced concurrently, so a child that fills one pipe while Guardian waits
/// on another cannot deadlock the review.
pub fn run(
    program: &Path,
    args: &[OsString],
    input: Option<&[u8]>,
    env: &[(&str, &str)],
    limits: Limits,
) -> Result<Captured, Error> {
    run_with(program, args, input, env, limits, None)
}

/// Like `run`, in `directory`, for a child that is fed `input` and must
/// not inherit the variables named in `unset`.
pub fn run_in_without(
    program: &Path,
    args: &[OsString],
    input: &[u8],
    directory: &Path,
    env: &[(&str, &str)],
    unset: &[&str],
    limits: Limits,
) -> Result<Captured, Error> {
    run_inner(
        program,
        args,
        Stdin::Bytes(input),
        env,
        unset,
        limits,
        Some(directory),
    )
}

/// Like `run`, in `directory` and without input.
pub fn run_in(
    program: &Path,
    args: &[OsString],
    directory: &Path,
    env: &[(&str, &str)],
    limits: Limits,
) -> Result<Captured, Error> {
    run_with(program, args, None, env, limits, Some(directory))
}

/// Like `run`, with `file` as the child's standard input: an archive opened
/// once is read by every pass, whatever happens to its path meanwhile.
pub fn run_with_stdin_file(
    program: &Path,
    args: &[OsString],
    file: fs::File,
    env: &[(&str, &str)],
    limits: Limits,
) -> Result<Captured, Error> {
    run_inner(program, args, Stdin::File(file), env, &[], limits, None)
}

enum Stdin<'a> {
    Null,
    Bytes(&'a [u8]),
    File(fs::File),
}

fn run_with(
    program: &Path,
    args: &[OsString],
    input: Option<&[u8]>,
    env: &[(&str, &str)],
    limits: Limits,
    directory: Option<&Path>,
) -> Result<Captured, Error> {
    let stdin = input.map_or(Stdin::Null, Stdin::Bytes);
    run_inner(program, args, stdin, env, &[], limits, directory)
}

fn run_inner(
    program: &Path,
    args: &[OsString],
    stdin: Stdin<'_>,
    env: &[(&str, &str)],
    unset: &[&str],
    limits: Limits,
    directory: Option<&Path>,
) -> Result<Captured, Error> {
    let input = match &stdin {
        Stdin::Bytes(bytes) => Some(*bytes),
        Stdin::Null | Stdin::File(_) => None,
    };
    let tool = program.file_name().map_or_else(
        || program.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );

    let mut command = Command::new(TIMEOUT);
    command
        .arg("--signal=TERM")
        .arg("--kill-after=5s")
        .arg(format!("{}s", limits.timeout_secs))
        .arg(program)
        .args(args)
        .stdin(match stdin {
            Stdin::Null => Stdio::null(),
            Stdin::Bytes(_) => Stdio::piped(),
            Stdin::File(file) => Stdio::from(file),
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in unset {
        command.env_remove(key);
    }
    for (key, value) in env {
        command.env(key, value);
    }
    if let Some(directory) = directory {
        command.current_dir(directory);
    }

    let mut child = command.spawn().map_err(|source| Error::Spawn {
        tool: tool.clone(),
        source,
    })?;
    let (stdout, stderr) = collect_output(&mut child, input, limits.max_output);
    let status = child.wait().map_err(|source| Error::ToolFailed {
        tool: tool.clone(),
        detail: format!("could not wait for exit: {source}"),
    })?;

    let stdout = stdout.map_err(|problem| match problem {
        OutputProblem::TooLarge => Error::OutputTooLarge {
            tool: tool.clone(),
            limit: limits.max_output,
        },
        OutputProblem::Read(source) => Error::ToolFailed {
            tool: tool.clone(),
            detail: format!("could not read output: {source}"),
        },
    })?;

    Ok(Captured {
        tool,
        status,
        stdout,
        stderr,
    })
}

enum OutputProblem {
    TooLarge,
    Read(io::Error),
}

fn collect_output(
    child: &mut Child,
    input: Option<&[u8]>,
    max_output: usize,
) -> (Result<Vec<u8>, OutputProblem>, Vec<u8>) {
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let pid = child.id();

    thread::scope(|scope| {
        if let (Some(mut pipe), Some(input)) = (stdin, input) {
            // A child that exits without reading its input closes the pipe;
            // its exit status reports that, so the write error adds nothing.
            scope.spawn(move || drop(pipe.write_all(input)));
        }
        let stderr_reader = stderr.map(|pipe| scope.spawn(move || read_capped(pipe, MAX_STDERR)));

        let mut stdout_bytes = Vec::new();
        let read = match stdout {
            Some(pipe) => pipe
                .take(max_output as u64 + 1)
                .read_to_end(&mut stdout_bytes)
                .map(drop)
                .map_err(OutputProblem::Read),
            None => Ok(()),
        };
        let result = match read {
            Err(problem) => Err(problem),
            Ok(()) if stdout_bytes.len() > max_output => Err(OutputProblem::TooLarge),
            Ok(()) => Ok(stdout_bytes),
        };
        if result.is_err() {
            // TERM makes `timeout` stop the program, then SIGKILL it after the
            // grace period, so no pipe stays open and the readers finish.
            terminate(pid);
        }

        let stderr_bytes = stderr_reader
            .map(|reader| reader.join().unwrap_or_default())
            .unwrap_or_default();
        (result, stderr_bytes)
    })
}

/// Reads up to `limit` bytes and discards the rest until end of file, so the
/// writer never blocks on a full pipe.
fn read_capped(mut pipe: impl Read, limit: usize) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) | Err(_) => return kept,
            Ok(count) => {
                let room = limit.saturating_sub(kept.len());
                kept.extend_from_slice(&buffer[..count.min(room)]);
            }
        }
    }
}

fn terminate(pid: u32) {
    // Best effort: if this fails the child still dies at its timeout.
    drop(
        Command::new(KILL)
            .args(["-s", "TERM", "--", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    );
}

/// Maps a child's exit status to this process's exit code, using the shell
/// convention of 128 + signal number for a child killed by a signal.
pub fn exit_code_of(status: ExitStatus) -> ExitCode {
    let code = status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1);
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::process::{ExitCode, ExitStatus};

    use super::{Limits, exit_code_of, find_in_path, run};
    use crate::error::Error;
    use crate::test_support::{TempDir, write_script};

    const LIMITS: Limits = Limits {
        timeout_secs: 30,
        max_output: 1024,
    };

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn captures_output_and_passes_input() {
        let captured = run(Path::new("/bin/cat"), &[], Some(b"hello"), &[], LIMITS).unwrap();
        assert!(captured.status.success());
        assert_eq!(captured.stdout, b"hello");
    }

    #[test]
    fn enforces_the_output_limit() {
        let result = run(
            Path::new("/bin/sh"),
            &args(&["-c", "yes"]),
            None,
            &[],
            LIMITS,
        );
        assert!(matches!(result, Err(Error::OutputTooLarge { .. })));
    }

    #[test]
    fn a_chatty_stderr_does_not_deadlock() {
        let captured = run(
            Path::new("/bin/sh"),
            &args(&["-c", "head -c 1048576 /dev/zero >&2; echo done"]),
            None,
            &[],
            LIMITS,
        )
        .unwrap();
        assert_eq!(captured.stdout, b"done\n");
        assert_eq!(captured.stderr.len(), 64 * 1024);
    }

    #[test]
    fn failures_report_stderr_and_timeouts() {
        let failed = run(
            Path::new("/bin/sh"),
            &args(&["-c", "echo broken >&2; exit 3"]),
            None,
            &[],
            LIMITS,
        )
        .unwrap();
        assert_eq!(failed.failure_detail(), "broken");

        let slow = run(
            Path::new("/bin/sh"),
            &args(&["-c", "sleep 5"]),
            None,
            &[],
            Limits {
                timeout_secs: 1,
                max_output: 16,
            },
        )
        .unwrap();
        assert_eq!(slow.failure_detail(), "timed out");
    }

    #[test]
    fn signal_deaths_map_to_128_plus_signal() {
        assert_eq!(exit_code_of(ExitStatus::from_raw(9)), ExitCode::from(137));
        assert_eq!(
            exit_code_of(ExitStatus::from_raw(3 << 8)),
            ExitCode::from(3)
        );
    }

    #[test]
    fn a_child_can_be_run_without_some_of_the_environment() {
        // PATH is set wherever tests run; the child is started by its
        // absolute path and does not need it.
        let seen = |unset: &[&str]| {
            let captured = super::run_in_without(
                Path::new("/usr/bin/env"),
                &[],
                b"",
                Path::new("/"),
                &[("GUARDIAN_TEST_KEPT", "1")],
                unset,
                Limits {
                    timeout_secs: 30,
                    max_output: 1024 * 1024,
                },
            )
            .unwrap();
            String::from_utf8_lossy(&captured.stdout).into_owned()
        };
        let all = seen(&[]);
        assert!(all.lines().any(|line| line.starts_with("PATH=")), "{all}");
        let without = seen(&["PATH", "GUARDIAN_TEST_NOT_SET"]);
        assert!(
            !without.lines().any(|line| line.starts_with("PATH=")),
            "{without}"
        );
        assert!(without.contains("GUARDIAN_TEST_KEPT=1"));
    }

    #[test]
    fn a_reviewer_in_a_place_others_can_write_is_refused() {
        use std::fs;
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        use super::{refuse_planted, scratch_directories};

        let dir = TempDir::new("reviewer-place");
        let me = Some(fs::metadata(dir.path()).unwrap().uid());
        let mode = |path: &Path, mode: u32| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        };
        let install = dir.path().join("opt/bin");
        fs::create_dir_all(&install).unwrap();
        mode(&install, 0o755);
        let binary = install.join("claude");
        write_script(&binary, "#!/bin/sh\n");
        mode(&binary, 0o755);
        // Nothing here is a scratch directory for this check.
        let nowhere = [dir.path().join("cache")];
        assert_eq!(refuse_planted(&binary, &nowhere, me), Ok(()));

        // The directory, or the file, writable by group or by everyone.
        for writable in [0o775, 0o757, 0o1777] {
            mode(&install, writable);
            let reason = refuse_planted(&binary, &nowhere, me).unwrap_err();
            assert!(
                reason.contains("the directory") && reason.contains("writable"),
                "{reason}"
            );
        }
        mode(&install, 0o755);
        mode(&binary, 0o775);
        let reason = refuse_planted(&binary, &nowhere, me).unwrap_err();
        assert!(reason.contains("the file"), "{reason}");
        mode(&binary, 0o755);

        // Under a temporary or cache directory, however it is protected.
        let cached = dir.path().join("cache/tool/bin");
        fs::create_dir_all(&cached).unwrap();
        mode(&cached, 0o700);
        write_script(&cached.join("claude"), "#!/bin/sh\n");
        let reason = refuse_planted(&cached.join("claude"), &nowhere, me).unwrap_err();
        assert!(reason.contains("temporary or cache directory"), "{reason}");
        // A link from a good directory into one is followed.
        let linked = install.join("opencode");
        symlink(cached.join("claude"), &linked).unwrap();
        assert!(refuse_planted(&linked, &nowhere, me).is_err());
        // And one that leads to a directory others can write.
        let shared = dir.path().join("shared");
        fs::create_dir(&shared).unwrap();
        mode(&shared, 0o777);
        write_script(&shared.join("real"), "#!/bin/sh\n");
        mode(&shared.join("real"), 0o755);
        let via = install.join("via");
        symlink(shared.join("real"), &via).unwrap();
        assert!(refuse_planted(&via, &nowhere, me).is_err());
        // A dangling link resolves to nothing.
        let dangling = install.join("dangling");
        symlink(dir.path().join("gone"), &dangling).unwrap();
        assert!(refuse_planted(&dangling, &nowhere, me).is_err());

        // The places that count: the temporary directories, the user's
        // cache, and a cache directory named in the environment.
        let scratch = scratch_directories(Some("/home/u".as_ref()), Some("/var/cache/u".as_ref()));
        for directory in [
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            "/home/u/.cache",
            "/var/cache/u",
        ] {
            assert!(
                scratch.contains(&Path::new(directory).to_path_buf()),
                "{directory}"
            );
        }
        assert_eq!(
            scratch_directories(None, Some("relative".as_ref())).len(),
            3
        );
        assert_eq!(scratch_directories(Some("".as_ref()), None).len(), 3);
    }

    /// A reviewer installed the way one is under a home directory:
    /// `home/.local/bin/claude`, the home private, the rest readable. Gives
    /// the binary and the owner of the fixture.
    fn installed(dir: &TempDir) -> (std::path::PathBuf, u32) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let home = dir.path().join("home");
        let install = home.join(".local/bin");
        std::fs::create_dir_all(&install).unwrap();
        for (directory, mode) in [
            (home.as_path(), 0o700),
            (&home.join(".local"), 0o755),
            (&install, 0o755),
        ] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let binary = install.join("claude");
        write_script(&binary, "#!/bin/sh\n");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        (binary, std::fs::metadata(dir.path()).unwrap().uid())
    }

    #[test]
    fn a_reviewer_in_the_users_own_directories_is_accepted() {
        use std::os::unix::fs::symlink;

        use super::refuse_planted;

        let dir = TempDir::new("reviewer-home");
        let (binary, owner) = installed(&dir);
        let me = Some(owner);
        assert_eq!(refuse_planted(&binary, &[], me), Ok(()));
        // Through a linked directory, and as a link to where a version is
        // kept.
        let home = dir.path().join("home");
        symlink(home.join(".local/bin"), home.join("bin")).unwrap();
        assert_eq!(refuse_planted(&home.join("bin/claude"), &[], me), Ok(()));
        let versions = home.join(".local/share/claude/versions");
        std::fs::create_dir_all(&versions).unwrap();
        write_script(&versions.join("1.0"), "#!/bin/sh\n");
        let linked = home.join(".local/bin/opencode");
        symlink("../share/claude/versions/1.0", &linked).unwrap();
        assert_eq!(refuse_planted(&linked, &[], me), Ok(()));
        // What the system installed is root's, whoever asks.
        assert_eq!(refuse_planted(Path::new("/bin/sh"), &[], me), Ok(()));
    }

    #[test]
    fn a_reviewer_that_belongs_to_another_user_is_refused() {
        use super::{is_foreign_owner, refuse_planted};
        use crate::test_support::{NOBODY, give};

        assert!(!is_foreign_owner(0, None));
        assert!(!is_foreign_owner(0, Some(1000)));
        assert!(!is_foreign_owner(1000, Some(1000)));
        assert!(is_foreign_owner(1000, Some(1001)));
        assert!(is_foreign_owner(1000, None));

        let dir = TempDir::new("reviewer-owner");
        let (binary, owner) = installed(&dir);
        assert_eq!(refuse_planted(&binary, &[], Some(owner)), Ok(()));
        if owner == 0 {
            // Root's own files are anyone's to use: hand them to another.
            for (entry, what) in [
                (binary.as_path(), "the file"),
                (binary.parent().unwrap(), "the directory"),
                (dir.path().join("home").as_path(), "the directory"),
            ] {
                if give(entry, NOBODY) {
                    let reason = refuse_planted(&binary, &[], Some(0)).unwrap_err();
                    assert!(
                        reason.contains(what) && reason.contains("belongs to another user"),
                        "{reason}"
                    );
                    assert!(give(entry, 0));
                }
            }
        } else {
            // Asked for by someone else, the same files are another user's.
            for other in [Some(owner + 1), None] {
                let reason = refuse_planted(&binary, &[], other).unwrap_err();
                assert!(
                    reason.contains("the file") && reason.contains("belongs to another user"),
                    "{reason}"
                );
            }
        }
    }

    #[test]
    fn a_reviewer_below_a_directory_others_can_write_is_refused() {
        use std::fs;
        use std::os::unix::fs::{PermissionsExt, symlink};

        use super::refuse_planted;

        let dir = TempDir::new("reviewer-above");
        let (binary, owner) = installed(&dir);
        let me = Some(owner);
        let mode = |path: &Path, mode: u32| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        };
        let home = dir.path().join("home");
        // A link from a good place to the same file is refused with it.
        let good = dir.path().join("good");
        fs::create_dir(&good).unwrap();
        mode(&good, 0o755);
        symlink(&binary, good.join("claude")).unwrap();
        for (above, restored) in [(home.join(".local"), 0o755), (home.clone(), 0o700)] {
            for writable in [0o775, 0o757, 0o777] {
                mode(&above, writable);
                for found in [&binary, &good.join("claude")] {
                    let reason = refuse_planted(found, &[], me).unwrap_err();
                    assert!(
                        reason.contains("the directory")
                            && reason.contains(&above.display().to_string())
                            && reason.contains("writable"),
                        "{reason}"
                    );
                }
            }
            // Sticky, as `/tmp` is: only its owner renames what is in it.
            mode(&above, 0o1777);
            assert_eq!(refuse_planted(&binary, &[], me), Ok(()));
            mode(&above, restored);
        }
        assert_eq!(refuse_planted(&binary, &[], me), Ok(()));
    }

    #[test]
    fn path_search_ignores_relative_entries() {
        let dir = TempDir::new("path-search");
        write_script(&dir.path().join("opencode"), "#!/bin/sh\n");

        let relative = OsString::from(format!("relative:{}", dir.path().display()));
        assert_eq!(
            find_in_path("opencode", &relative),
            Some(dir.path().join("opencode"))
        );
        assert_eq!(find_in_path("opencode", &OsString::from(".:bin")), None);
    }
}
