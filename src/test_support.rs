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

/// The user `nobody`: the second account of a test that runs as root.
pub const NOBODY: u32 = 65534;

/// Makes `path` (itself, not what is below it, and not what a link leads
/// to) the user `owner`'s. Only root can, and not root of a user namespace
/// that maps no such user: `false` then, for the test to do without.
pub fn give(path: &Path, owner: u32) -> bool {
    std::os::unix::fs::lchown(path, Some(owner), None).is_ok()
}

/// Makes `path` and everything below it the user `owner`'s, as [`give`]
/// does for one; `false` as soon as one cannot be given.
pub fn give_tree(path: &Path, owner: u32) -> bool {
    if !give(path, owner) {
        return false;
    }
    let below = fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir());
    !below
        || fs::read_dir(path).is_ok_and(|entries| {
            entries
                .flatten()
                .all(|entry| give_tree(&entry.path(), owner))
        })
}

/// Makes `path` in a fixture, and what is below it, a user's own, as a
/// home or a crontab is. A test run by a user owns it already; run by root
/// (a container), everything in the fixture is root's, and it is given to
/// [`NOBODY`]. `false` where that cannot be done (root of a user namespace
/// with no such user), for the test to do without.
pub fn owned_by_a_user(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).is_ok_and(|metadata| metadata.uid() != 0) || give_tree(path, NOBODY)
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
        r#"$(printf '%s\n' "$input" | sed -n 's/^Nonce: //p' | tr -d '\n')"#
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
nonce=$(printf '%s\n' "$input" | sed -n 's/^Nonce: //p' | tr -d '\n')
reply="{{\"nonce\":\"$nonce\",\"status\":\"clear\",\"summary\":\"mock\",\"findings\":[]}}"
escaped=$(printf '%s' "$reply" | sed 's/"/\\"/g')
printf '{{"type":"text","part":{{"type":"text","text":"%s"}}}}\n' "$escaped"
"#
        ),
    );
    binary
}

/// A small deterministic generator (xorshift64*) for property tests: the
/// same seed gives the same cases on every run and every machine, so a
/// failure can be run again.
pub struct Rng(u64);

impl Rng {
    pub const fn new(seed: u64) -> Self {
        // The state must never be zero.
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    pub const fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number below `bound`, which must not be zero.
    pub fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
    }

    /// True once in `one_in` times.
    pub fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// Up to `most` pieces of `alphabet`, joined: text made of the pieces
    /// a format is written with reaches far more of a parser than bytes
    /// drawn evenly.
    pub fn text(&mut self, alphabet: &[&str], most: usize) -> String {
        (0..self.below(most + 1))
            .map(|_| *self.pick(alphabet))
            .collect()
    }

    /// `text` with a few of its bytes dropped, repeated, swapped for one
    /// of `alphabet`'s or cut short, as text again (a broken sequence
    /// becomes the replacement character).
    pub fn mutated(&mut self, text: &str, alphabet: &[&str]) -> String {
        let mut bytes = text.as_bytes().to_vec();
        for _ in 0..=self.below(4) {
            if bytes.is_empty() {
                break;
            }
            let at = self.below(bytes.len());
            match self.below(5) {
                0 => drop(bytes.remove(at)),
                1 => bytes.insert(at, bytes[at]),
                2 => bytes.truncate(at),
                3 => {
                    let other = self.below(bytes.len());
                    bytes.swap(at, other);
                }
                _ => {
                    let piece = self.pick(alphabet).as_bytes().to_vec();
                    bytes.splice(at..at, piece);
                }
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }
}
