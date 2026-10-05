# Development

For people who change Guardian: the checks to run, the unit and end-to-end
test suites and what each needs, how the AI review is measured after a change
to its request text, and how the maintainer cuts and signs a release.

## Contents

- [Checks](#checks)
- [End-to-end suites](#end-to-end-suites)
- [Measuring a change to the request text](#measuring-a-change-to-the-request-text)
- [Documentation](#documentation)
- [Cutting a release](#cutting-a-release)

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
```

On a non-Linux workstation, check with `cargo clippy --target
x86_64-unknown-linux-gnu --all-targets -- -D warnings` (the crate refuses to
build for other systems). Local hooks run the same checks: `prek install` (see
`.pre-commit-config.yaml`). CI runs them on an Arch Linux container, with the
shell scripts' syntax and lint, and the offline gate suite below.

The unit tests include property tests for the hand-written parsers (JSON, the
TOML subset, the settings file, makepkg's source listing, pacman's mtree
records, getcap's output): a small deterministic generator feeds them
generated and damaged input, the same on every run. They check that no input
panics, that what is written is read back as it was, that nesting stops at its
limit, that a key given twice is refused however it is spelled, and that an
accepted settings file is written back to the same settings.

## End-to-end suites

There are four end-to-end suites. All need `cargo build --release` first; none
installs anything or touches the real home.

| Suite | Calls the AI | Needs | In CI |
| --- | --- | --- | --- |
| `tests/e2e/gates-offline.sh` | no | `bsdtar`, `pacman-conf`, `setsid`; `bwrap`, `makepkg`, `lua`, `git` and `ssh-keygen` for some cases | yes |
| `tests/e2e/sweep.sh` | no | `bwrap` 0.9 or newer (overlays), `jq` | no: it needs user namespaces, which a hosted container does not give |
| `tests/e2e/integration-gates.sh` | yes | `bwrap` 0.9 or newer, `bsdtar`, `pacman`, `git`, `flock`, `curl`, a reviewer | no |
| `tests/ai-eval/run.sh` | yes, several times per case | `bsdtar`, `makepkg`, `bwrap`, `jq`, a reviewer | no |

```sh
cargo build --release
bash tests/e2e/gates-offline.sh
bash tests/e2e/sweep.sh
bash tests/e2e/integration-gates.sh
```

### `gates-offline.sh`

`gates-offline.sh` covers what the gates decide before a review, or with no
reviewer to ask, with the real binary and scripts: the pacman hook script
letting transactions through until it is turned on, and stopping them once it
is; the refusals of the pacman gate that need no review (a removal, a parent
that is not pacman, a missing or mismatched archive, files in `/usr/sbin`, the
reviewer's settings shipped by a local package, a reviewer from `PATH` for
root's pacman); Guardian's own package, put together by its PKGBUILD's
`package()`, through its own gate; `guard`, `scan`, `sandbox` and the makepkg
gate stopping on a broken user settings file, on a question nobody can answer,
and never exiting 0 without starting the command; the makepkg gate's own jail
with the AI off (listing, fetching, `--holdver`, the later call held against
what was extracted, the two questions); the commands on PATH and the Bash
interceptor routing every spelling of a theme or plugin install to Guardian
and help to Omarchy; the `omarchy` wrapper finding Omarchy's own dispatcher in
either place and never on PATH; the file Hyprland loads putting Guardian's
commands first whatever PATH it starts from; what the installer takes for a
signed release (an added file, a file the checkout's own exclude list hides, a
changed file, an unknown key, and a checkout whose `.git/config` names its own
keys file or verifying program); and the bar's check that the interceptor's
line is in effect. `opencode` and `claude` on its `PATH` are stand-ins, and
the suite fails if either is ever started. A case whose requirement is missing
is reported as skipped, and one known to fail today is run, shown as `KNOWN`
with the reason and counted apart.

The pacman gate's cases run twice: as a user with the stand-in reviewers, and
as root, where the gate looks for the root-owned reviewer it would really use.
Run as a user, "as root" is root of a user namespace (Bubblewrap) with a root
directory of its own; a reviewer installed on the system is hidden from those
cases behind a private mount, so they run whatever is installed and none is
asked. In CI the suite runs as real root in a throwaway container, and there,
and only there (`CI=true`, as root), it changes the system for the length of
two checks: it creates and removes the link
`/etc/pacman.d/hooks/omarchy-guardian.hook`, and installs and removes
`/usr/bin/omarchy-guardian`, to run the hook script turned on as pacman would.
As root anywhere else those checks are skipped.

### `integration-gates.sh`

`integration-gates.sh` runs the real hook, shim and theme handler in a
Bubblewrap sandbox with a throwaway `/usr` overlay, mock `makepkg` and
`omarchy-theme-set`, a simulated pacman parent process and a throwaway `HOME`,
and reviews with the real reviewer: clean and malicious install scripts,
recipes, upstream sources and themes, the review memory (cache, upgrade as a
diff, the chunk limit) and the settings. It needs a working `opencode`, and
exits `77` when it cannot run or sits where Guardian would refuse it (a
directory others can write, or a temporary one), because every gate is
fail-closed on a failed AI review. To review with the Claude Code CLI and your
Claude login instead, set `GUARDIAN_E2E_MODEL=claude-code/claude-sonnet-5-5`
(the pacman checks that need the AI are then skipped, because the pacman gate
takes its model only from a root-owned system config). Its scratch directory
must not be under `/tmp`, which the sandbox empties; by default it is under
`$XDG_RUNTIME_DIR`.

### Notifications in the harnesses

The harnesses set `OMARCHY_GUARDIAN_NO_NOTIFY`, since their blocks are
expected: with it set no pop-up is shown and no browser opened. It silences
nothing else: the report of a block is still saved (the harnesses point
`XDG_CACHE_HOME` at their own directory, so those reports stay out of yours
and of the bar). The pacman hook's `--opencode-from-path` is for these
harnesses too, whose pacman is a script of yours; it is refused when the
pacman process belongs to root.

### `sweep.sh`

`sweep.sh` plants persistence the way PANIX and real Linux malware set it up
(enabled services, cron, udev, modprobe, the dynamic linker, PAM, profile
scripts, autostart, generators, pacman hooks, NetworkManager dispatchers,
initramfs hooks, a setuid shell copy, a replaced setuid binary, Hyprland Lua,
Omarchy hooks, `~/.local/bin` shadowing, a launcher override, git and SSH, a
program running from the cache, overrides of Guardian's own units) into
throwaway `/etc` and `/usr` overlays and a throwaway `HOME`, and one sweep
must list every planted item and flag the plainly malicious ones; `--diff` is
checked too, and that `sweep allow`, which needs root, fails there and changes
nothing. The `system` class's AI review is off inside it. A sweep reads every
file of `/usr/bin` and the libraries, so the suite takes a few minutes.

### `tests/ai-eval/run.sh`

`tests/ai-eval/run.sh` measures the AI review itself: install scriptlets,
auto-run package files, AUR recipes, themes, plugins and files already on a
system (found by `sweep`) that must come back clear, and attacks that must be
caught. An upgrade case holds two versions of one source: the first must be
approved, and the second is then reviewed against it. Run it after changing a
prompt, a scope or the model:

```sh
cargo build --release
bash tests/ai-eval/run.sh                 # or a filter: run.sh aur/block
```

Each case is reviewed three times (`RUNS=N` changes that) and gets a line with
its pass rate; the run ends with the rates of the block and the clear cases
and exits non-zero when any case passed less than every run. Some block cases
attack the reviewer itself: text addressed to it in a comment or a README
(with and without a harmful action beside it), an instruction in invisible
characters, a command put together from two files, and an upgrade that
switches on a file the approved version already had.

Every run starts with an empty review memory, so no verdict comes from the
cache. The pacman cases use the system config's model, the AUR, theme, plugin,
upgrade and system cases the user config's. A system case is judged by the
AI's own medium or high findings on its planted files, since the rest of the
real system decides the sweep's exit code; the host's own files no package
vouches for are reviewed alongside (and sent to the provider), so results can
differ from machine to machine.

A case counts only when the AI was asked: a review that came out unavailable,
incomplete or limited (the gate found nothing it reviews) is shown as `I` and
fails the case, clear or block. A clear case must not match a local rule
either, since for a local package that blocks whatever the AI says.

The AUR cases run the makepkg gate in a Bubblewrap sandbox where a stand-in is
`/usr/bin/makepkg`, because the gate's own jail shows nothing else of the
run's directory; the stand-in lets the listing and the extraction through to
the real makepkg and never builds.

## Measuring a change to the request text

A change to the text of the request (`src/engine/request.rs`; its
`PROMPT_VERSION` is 13) is measured before it is released, not waved through
on one green run: review a small source 20 or more times with a fresh state
directory each time (`XDG_STATE_HOME=<scratch> omarchy-guardian scan --class
aur <dir>`, removing the directory between runs so nothing is cached) and
count the replies that fail. With unchanged request text about one real call
in 200 misses the nonce; an exit 2 in `integration-gates.sh` after a
request-text change is a result to count, not a flake to rerun away. A new
`PROMPT_VERSION` also retires every approved baseline and cached verdict, so
the first review of each source after the upgrade is a full one.

## Documentation

`tests/docs-links.sh` checks the documentation: every relative link in
`README.md`, `SECURITY.md` and `docs/*.md` names a file that exists, every
`#anchor` matches a heading of its target, and every page under `docs/` is
listed in the README's documentation index. It needs no network, and CI runs
it.

## Cutting a release

For the maintainer. A release is a version bump in `Cargo.toml`, `Cargo.lock`
and `packaging/arch/PKGBUILD`, merged, and an annotated tag `vX.Y.Z` on that
commit, signed with an SSH key:

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/release_key.pub    # the public half
git tag -s vX.Y.Z -m "Omarchy Guardian X.Y.Z"
git push origin vX.Y.Z
```

The keys that may sign a release are listed in `packaging/allowed_signers`,
one line each, in ssh-keygen's allowed-signers format:

```text
maintainer@example.org namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…
```

The first word is the principal (an address or any name), `namespaces="git"`
limits the key to git signatures, and the rest is the public key as in the
`.pub` file. The package installs that file as
`/usr/share/omarchy-guardian/allowed_signers`, and the installed
`/usr/lib/omarchy-guardian/upgrade` (and `install.sh`) check the next
release's tag against the installed copy. So a new key takes effect one
release after it is added: sign the release that adds it with the old key, and
only later ones with the new. The first release that carries the file (0.8.0)
cannot itself be verified by a Guardian installed before it, which has no
keys: that upgrade is trust on first use, checked by hand at best ([Verifying
a release](install.md#verifying-a-release)).

Keep the private key off the machines that build and test; check a tag before
pushing it with `git -c gpg.format=ssh -c
gpg.ssh.allowedSignersFile=packaging/allowed_signers verify-tag
refs/tags/vX.Y.Z`. A package built from a tree without the file installs none;
the upgrade check then refuses to build, and the installer says that the
signature was not checked.

The upgrade check holds a release to three things beyond the signature, so
keep to them: the tag is named `vX.Y.Z` (digits and dots, optionally `-N`), it
is an annotated tag whose own name is the name it is pushed under, and
`pkgver`-`pkgrel` in the tagged `packaging/arch/PKGBUILD` is not lower than
the previous release's. The export is made with `git archive`, so a path
marked `export-ignore` in the tagged `.gitattributes` would be missing from
the build.
