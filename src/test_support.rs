//! Helpers shared by unit tests.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A temporary directory removed on drop, even when the test panics.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "guardian-test-{label}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.path));
    }
}

pub fn write_script(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

/// Tests that need an Arch tool skip themselves where it is missing.
pub fn tool_available(path: &str) -> bool {
    Path::new(path).is_file()
}

/// A fake `opencode` that records its argv and stdin next to itself, insists
/// on the deny-all permission config, and answers with `status`. With
/// `echo_nonce` false it answers with the wrong nonce.
pub fn mock_opencode(dir: &Path, status: &str, echo_nonce: bool) -> PathBuf {
    mock_opencode_then(dir, status, echo_nonce, "")
}

/// [`mock_opencode`] followed by the shell lines in `after`, for events or
/// an exit status that come after the reply.
pub fn mock_opencode_then(dir: &Path, status: &str, echo_nonce: bool, after: &str) -> PathBuf {
    let binary = dir.join("opencode");
    let nonce = if echo_nonce {
        r#"$(printf '%s\n' "$input" | sed -n 's/^Nonce: //p')"#
    } else {
        "wrong"
    };
    write_script(
        &binary,
        &format!(
            r#"#!/bin/sh
dir=$(dirname "$0")
printf '%s\n' "$@" >"$dir/args"
case "$OPENCODE_CONFIG_CONTENT" in *'"*":"deny"'*) ;; *) exit 8 ;; esac
input=$(cat)
printf '%s\n' "$input" >"$dir/stdin"
nonce={nonce}
reply="{{\"nonce\":\"$nonce\",\"status\":\"{status}\",\"summary\":\"mock\",\"findings\":[]}}"
escaped=$(printf '%s' "$reply" | sed 's/"/\\"/g')
printf '{{"type":"text","part":{{"type":"text","text":"%s"}}}}\n' "$escaped"
{after}
"#
        ),
    );
    binary
}

/// A fake `opencode` that fails the way a provider or model error does.
pub fn mock_opencode_failing(dir: &Path, stderr: &str) -> PathBuf {
    let binary = dir.join("opencode");
    write_script(
        &binary,
        &format!("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{stderr}' >&2\nexit 1\n"),
    );
    binary
}

/// A fake `opencode` that prints `stdout` verbatim and exits with `code`.
pub fn mock_opencode_output(dir: &Path, stdout: &str, code: i32) -> PathBuf {
    let binary = dir.join("opencode");
    write_script(
        &binary,
        &format!("#!/bin/sh\ncat >/dev/null\ncat <<'EOF'\n{stdout}\nEOF\nexit {code}\n"),
    );
    binary
}

/// A fake `opencode` whose first `good_calls` calls answer clear with the
/// right nonce; every later call runs the shell lines in `then` instead. The
/// number of calls is kept in `count` next to it; concurrent calls are
/// counted under a lock.
pub fn mock_opencode_counting(dir: &Path, good_calls: u32, then: &str) -> PathBuf {
    let binary = dir.join("opencode");
    write_script(
        &binary,
        &format!(
            r#"#!/bin/sh
dir=$(dirname "$0")
input=$(cat)
count=$(flock "$dir/count" sh -c 'c=$(( $(cat "$1" 2>/dev/null || echo 0) + 1 )); echo "$c" >"$1"; echo "$c"' sh "$dir/count")
if [ "$count" -gt {good_calls} ]; then
{then}
exit 0
fi
nonce=$(printf '%s\n' "$input" | sed -n 's/^Nonce: //p')
reply="{{\"nonce\":\"$nonce\",\"status\":\"clear\",\"summary\":\"mock\",\"findings\":[]}}"
escaped=$(printf '%s' "$reply" | sed 's/"/\\"/g')
printf '{{"type":"text","part":{{"type":"text","text":"%s"}}}}\n' "$escaped"
"#
        ),
    );
    binary
}
