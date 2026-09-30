# Omarchy Guardian

Omarchy Guardian inspects downloaded source code before you run or install it
on Arch Linux / Omarchy. It is an early, heuristic tool: a clear result is not
a safety guarantee.

It is a single Rust binary with **no third-party crates**. SHA-256, JSON, and
the small subset of TOML it needs are implemented in the crate so the whole
gate can be audited in one place. It builds only for Linux.

## Commands

```sh
omarchy-guardian scan ./downloaded-project
omarchy-guardian scan --thorough --hashes ./theme-checkout
omarchy-guardian guard --thorough ./aur-build-directory -- makepkg --noconfirm
omarchy-guardian sandbox ./theme-checkout -- /usr/bin/true
```

- `scan` reviews a file or directory and prints a report.
- `guard` reviews, then re-hashes the tree, then **replaces itself** with the
  command (`exec`) only if the review was clear and nothing changed.
  `--exclude NAME` (repeatable) leaves a top-level directory out of both the
  review and the snapshot.
- `tui` (or `settings`) opens the settings app: a full-screen terminal UI in
  Omarchy's style, simple by default, with every setting under `--expert`
  (see [Settings app](#settings-app)).
- `sandbox` reviews, copies the tree to a private temporary directory, proves
  the copy matches the reviewed snapshot, and runs the command in Bubblewrap
  with the network isolated, no host home directory and a read-only system.
  It is a behaviour smoke test, not a dynamic malware detector.
- `--identity ID` or `--unit DIR ID` (repeatable) on `scan`, `guard` and
  `sandbox` name what is reviewed for the review memory (see
  [How the review scales](#how-the-review-scales)); `omarchy-guardian forget
  ID` drops that source's baselines (cached verdicts are kept) and `forget
  --all` clears everything.

Exit codes: `0` clear, warned or limited review (a scriptlet-free pacman
transaction); `1` findings; `2` an incomplete review, an unavailable AI review
under `ai = required`, a declined confirmation, or a usage error. Once `guard`
or `sandbox` starts the command, the exit code is the command's own (128 +
signal if it was killed). Guardian announces on stderr when it starts the
command, so its own blocks can be told apart from the command's failures.

## Settings app

`omarchy-guardian tui` edits every setting without touching TOML by hand.
It installs a launcher entry ("Omarchy Guardian") that opens as a floating
window, and can add itself to the Omarchy menu under Setup › Guardian.

It opens in **simple mode**, where the Guardian (the app's mascot) tells you
how you are protected. Here you choose a protection level, which sets the
profile for your own sources and for pacman alike:

| Level | Profile | |
|---|---|---|
| Balanced | `standard` | AI review for AUR builds, themes and third-party packages |
| Maximum | `strict` | AI review for everything; any finding blocks |
| Private | `local-only` | no AI: nothing leaves the machine; you confirm installs |

You can also pick the OpenCode model used for both, turn on every install
gate at once (*Protect everything*), or reset to the defaults.

Press `e` for **expert mode** (or start there with `tui --expert`), which
has every setting:

| Tab | What it changes |
|---|---|
| Profiles | the profile for your own sources (user file) and for the pacman gate (system file) |
| Sources | every knob of every source class; pacman-enforced classes in the system file, the rest in the user file |
| AI | model, input size and call limits for your sources and for the pacman gate, review-memory limits, official repositories |
| Integrations | turn the pacman hook, the yay AUR gate, the theme & plugin gate and the Omarchy menu entry on or off |
| Maintenance | show and check the effective settings, edit either file in `$EDITOR`, see or forget the review memory, run the guided setup |

Unset values show what they inherit and from where. Keys: `↑↓` move,
`Tab`/`1`–`5` switch tabs, `Enter` edit, `Space` cycle a choice, `x` reset to
inherit, `u` undo, `s` save, `e` back to simple mode, `q` quit. Every edit
is checked with the same parser that reads the files, so the app cannot save
a file Guardian would reject. The user file is written directly (a hand-written one is kept as
`config.toml.bak`, since comments are not preserved). The system file is
saved only after showing a diff, with `sudo`, like `setup` does. A file that
does not parse cannot be edited in the app; fix it with Maintenance › Edit.

## Profiles and settings

Every review is tagged with the class of its source. Classes reviewed by the
pacman hook are *privileged*: Guardian's own settings for them can only be
loosened by the system file (but see the OpenCode caveat below).

| Class | Source | Enforced by | Privileged |
|---|---|---|---|
| `official` | `pacman -S` from a repo in `official_repos` whose SigLevel requires signatures | pacman hook | yes |
| `third-party-repo` | `pacman -S` from any other repo, signed or not | pacman hook | yes |
| `local-package` | `pacman -U` archives | pacman hook | yes |
| `aur` | yay makepkg shim | user | no |
| `theme` | Omarchy theme install/update handler | user | no |
| `plugin` | Omarchy plugin gate (`omarchy plugin add` / `update`) | user | no |
| `source` | explicit `scan` / `guard` / `sandbox` (default) | user | no |

`official_repos` defaults to `core, extra, multilib, core-testing,
extra-testing, multilib-testing, omarchy` and is settable only in the system
file. A repo counts as `official` only if it is listed **and** its SigLevel
requires signatures; otherwise its packages are `third-party-repo`. That
includes Omarchy's own `[omarchy]` repo when its `pacman.conf` entry uses
`SigLevel = Optional` or `TrustAll`; check with
`pacman-conf --repo=omarchy SigLevel`.

A profile is a named preset for every knob (`ai`, `on_findings`,
`on_ai_suspicious`, `thinking`, `confirm`, `cache`, `diff`) of every class:

| Profile | `official` | other classes |
|---|---|---|
| `standard` (default) | `ai = optional`, `thinking = low`, `on_findings = warn`, `on_ai_suspicious = block` | `ai = required`, `thinking = high`, `on_findings = block`, `on_ai_suspicious = block` |
| `strict` | `ai = required`, `thinking = medium`, `on_findings = block`, `on_ai_suspicious = block` | `ai = required`, `thinking = max`, `on_findings = block`, `on_ai_suspicious = block` |
| `local-only` | `ai = off`, `on_findings = warn` | `ai = off`, `on_findings = block`, plus `confirm = true` for user-level classes |

`cache` and `diff` are `on` for user-level classes (`diff` is `off` under
`strict`) and always `off` for the pacman classes, where setting them is a
config error.

`confirm` only applies with `ai = off`, on the user-level classes (the pacman
hook has no reliable terminal): after clean local checks it asks on
`/dev/tty` whether to proceed; no terminal or no explicit yes blocks the run.

Settings come from two files of the same format:

- system: `/etc/omarchy-guardian/config.toml`
- user: `$XDG_CONFIG_HOME/omarchy-guardian/config.toml`, default
  `~/.config/omarchy-guardian/config.toml`

For the privileged classes, a user-file value for a knob applies only when it
is at least as strict as the value from the profile and system file, and
`thinking`, `model`, `timeout_secs`, `[agent]`, `[agent.variants]` and
`official_repos` are never taken from the user file or a user profile at all
for those classes. For the user-level classes, the
user file's values apply directly, since those commands never reach the
privileged pacman gate.

```toml
profile = "standard"             # standard | strict | local-only

official_repos = ["core", "extra", "multilib", "omarchy"]   # system file only

[agent]
model = "anthropic/claude-sonnet-5"   # omit for OpenCode's default
max_input_kib = 256                   # 16..=1024, per AI call
max_chunks = 8                        # 1..=64 AI calls per review
cache_days = 30                       # 0..=365; 0 turns the verdict cache off
max_store_mib = 256                   # 16..=4096, review memory size cap

[agent.variants]                      # portable level -> provider variant
high = "high"
max = "xhigh"

[class.official]
model = "anthropic/claude-haiku-4-5"
thinking = "low"

[class.aur]
thinking = "max"
on_findings = "block"
ai = "required"
timeout_secs = 300
cache = "on"                          # user-level classes only
diff = "on"                           # off under the strict profile
```

A thinking level is only sent to OpenCode (as `--variant`) when
`[agent.variants]` maps it, because variant names differ between providers.
An unmapped level uses the provider's default and is shown as, for example,
`high (provider default)` in `config show` and in reports. `setup` writes the
mapping for the level its test run passed with, in both files.

The pacman hook runs the review as the invoking user from an empty
environment, without a login shell, so shell rc files and exported variables
cannot affect it. OpenCode still reads that user's own OpenCode configuration
and credentials under `~`, so the provider endpoint and the default model
used by the pacman gate remain under the user's control; a root-owned
OpenCode configuration would be needed to close that, and Guardian does not
set one up yet.

- `omarchy-guardian setup` — interactive wizard that detects OpenCode and
  Claude Code (suggesting Claude Sonnet when `claude` is installed), lets
  you choose a profile, model(s) and thinking level, runs a two-sample test
  review, then writes the user file and (with confirmation) the root-owned
  system file.
- `omarchy-guardian config show [--class NAME]` — effective policy per class,
  each value tagged `profile`, `system` or `user`, plus any ignored user
  values and why.
- `omarchy-guardian config check` — validates both files and the system
  file's ownership; exit 0 valid, 2 invalid.
- `omarchy-guardian config path` — prints both file paths.

`scan` and `guard` take `--class NAME` (default `source`; one of the
user-level classes `aur`, `theme`, `plugin`, `source`) to tag the review with
its source class. `scan`, `guard` and `sandbox` take `--profile NAME`
(`standard`, `strict`, `local-only`) to override the profile for that one run;
it cannot affect a privileged class, because these commands never review one.
The yay shim passes `--class aur`; the Omarchy theme handler passes
`--class theme`.

| Decision | Exit | When |
|---|---|---|
| `CLEAR` | 0 | nothing found, review complete |
| `WARNED` | 0 | only findings whose policy is `warn`, or the AI review was unavailable under `ai = optional` |
| `LIMITED REVIEW` | 0 | nothing reviewable (a scriptlet-free pacman transaction) |
| `HIGH RISK` / `REVIEW REQUIRED` | 1 | any finding whose policy is `block` |
| `INCOMPLETE` | 2 | any non-AI gap, or an invalid AI reply (malformed, missing nonce, tool use, `inconclusive`), in every profile |
| `AI REVIEW UNAVAILABLE` | 2 | the AI review was unavailable under `ai = required` |
| `NOT CONFIRMED` | 2 | `confirm = true` and the user did not approve |

Upgrading users on the default `standard` profile: official Arch/Omarchy
packages now `WARN` on local-rule findings and proceed without the AI review
when it is unavailable, where they used to block. To restore the old
behaviour, set in the system file:

```toml
[class.official]
ai = "required"
on_findings = "block"
```

## How the review scales

Large sources are reviewed in several AI calls (chunks) instead of being
refused. Files are ranked by risk:

1. Build and install entry points go first and are always sent whole:
   `PKGBUILD`, `.install`, `Makefile`, `GNUmakefile`, `CMakeLists.txt`,
   `meson.build`, `build.rs`, `setup.py`, `pyproject.toml`, `package.json`,
   top-level `*.sh`, systemd units, `.desktop` files, Hyprland `exec`
   config, plugin QML, and any file with a local finding.
2. Other code and runtime config follow.
3. Everything else, with documentation last.

Each chunk is its own reviewer run with its own nonce, and every chunk carries
the full file list, so the model knows what else exists. The first chunk runs
alone; the rest run three at a time. A run that finds the AI unavailable (a
provider error, not a timeout) is retried once after two seconds; if it still
fails, chunks not yet started are not attempted. A source that needs
more than `max_chunks` chunks of `max_input_kib` is not reviewed at all
(`INCOMPLETE`): a partial AI review is never presented as a review of the
whole source.

For user-level sources (AUR, themes, plugins and `scan`/`guard`/`sandbox`
targets), Guardian keeps a review memory in
`$XDG_STATE_HOME/omarchy-guardian`, default
`~/.local/state/omarchy-guardian`, mode 0700. Guardian creates it (and any
missing parents) only under an existing directory you own (a symlink counts
as its target), so a run under
`sudo -E` leaves nothing owned by root in your home; otherwise the report
says the memory was not used and the review runs in full:

- **Verdict cache.** A chunk already judged `clear` or `suspicious`, with the
  same prompt, model, variant, thinking level and class, is not sent again
  for `cache_days` (default 30). Reports mark such chunks `from cache`.
- **Diff review of upgrades.** A review becomes the approved baseline of that
  source when every chunk was `clear`, there were no gaps, and the decision
  is `CLEAR`. The next review of the same source is then sent as follows:
  changed files as unified diffs against the baseline, new files and entry
  points whole, and unchanged files only as names in the file list. Local
  rules and the dependency audit still read every file. A baseline only
  counts under the prompt version, model, variant and thinking level that
  approved it; after any of them changes, the next review is a full one. A
  source identical to its baseline is answered from the cache when its first
  review is still cached (yay's second `makepkg` pass); otherwise it is
  reviewed as an upgrade like any other. The `strict` profile turns diff
  review off.

The AUR gate remembers a build by yay's build directory name, and the theme
handler remembers a theme by its name. Other targets are remembered by their
class and path. `omarchy-guardian forget ID` drops one source's baselines
but keeps cached verdicts, so an unchanged rebuild can still be answered from
the cache; `omarchy-guardian forget --all` also clears every cached verdict.
`config show` prints the memory's location and size.

The pacman gate never uses this memory: every scriptlet gets a fresh, full
review. Because the memory lives in your home directory, malware already
running as your user could plant a cached `clear` verdict. Such malware could
equally edit your shell startup files, so the user-level gates never
defended against it. Set `cache = "off"` and `diff = "off"` for a class to
review it in full every time.

## What is checked

- **Local rules** on every text file except prose (`*.md`, `*.rst`, `README`,
  license and legal texts such as `LICENSE.txt`, `COPYING.LESSER`,
  `terms.html` or anything under `LICENSES/`, PKGBUILD `*.changelog` files, ...): download-to-shell pipelines, encoded command execution,
  credential file access, destructive commands (a recursive `rm` of `/` or
  `$HOME` itself, `mkfs`, raw-disk writes), persistence, shell execution,
  privilege escalation, disabled TLS verification and likely credential
  exfiltration. Identifier patterns respect word boundaries, so `retrieval(`
  and `model.eval()` do not match `eval(`. Making a Chromium-family sandbox
  helper setuid root (`chmod 4755` or `chown root` of `chrome-sandbox`,
  `msedge-sandbox`, `opera_sandbox`, ...), which every Chromium and Electron
  package does, is not a privilege-escalation finding. A persistence path a
  PKGBUILD writes into its own package (`"$pkgdir"/etc/profile.d/...`,
  without `..`) is a package file, not persistence. A `mkfs.*` program that is
  only installed, copied or linked is not run, so it is not a destructive
  command. Comments are skipped (shell and
  other `#` languages, `//` and `/* */` in C-like languages, Lua `--`, and
  comment lines a patch adds to a file of one of those languages). Lines a
  patch removes are skipped by the same checks as printed text below, since
  `patch -R` would apply them. In shell scripts, text that is only printed
  (`echo` and `printf` arguments, `cat <<EOF` bodies, when nothing pipes,
  redirects or substitutes them) is skipped by the persistence, privilege,
  credential-file, TLS and network checks, so install notes like
  `echo "run: sudo systemctl enable foo"` are not findings; download-to-shell,
  encoded execution, destructive commands and shell execution still match
  printed text. Nothing printed is skipped in a script that redefines `echo`,
  `printf` or `cat`, enables aliases, pipes anything into an interpreter
  (`f | sh`, `| sudo bash`, `| xargs`), or redirects its own output with
  `exec` or a process substitution, since its messages may then run. Prose, comments and messages are still sent to the AI review.
- **Network destinations:** literal HTTP(S) hosts in code and runtime config,
  flagging cleartext HTTP and hard-coded IP addresses. A PKGBUILD's `url=`
  homepage (never fetched), XML namespace, DTD and schema identifiers are not
  destinations. URL paths, queries and credentials are never printed.
- **Dependencies:** `Cargo.lock`, npm lockfiles, `poetry.lock`, `go.sum` and
  exactly pinned `requirements*.txt` are checked with the public OSV API (only
  package names and versions are sent). Advisory severities and summaries are
  fetched per advisory; ones OSV does not rate are shown as `UNRATED`. Any
  advisory blocks a gate. Unsupported lockfiles, manifests with dependencies
  but no lockfile, or an unavailable OSV API make the review incomplete.
- **AI review:** the reviewable text is sent, in chunks of up to
  `max_input_kib` (default 256 KiB, at most `max_chunks` per review; see
  [How the review scales](#how-the-review-scales)), to the OpenCode CLI **on
  stdin** (never in argv, which is size-limited and visible to other users)
  with every OpenCode tool and permission denied. The reply must echo a
  random per-run nonce that only exists in that input, so a reply that never
  saw the source is rejected. Files that look sensitive by path (`.env*`, SSH
  and cloud credentials, key files, names containing `secret`, `credential` or
  `token`) are withheld and make the review incomplete.
- **Integrity:** a SHA-256 manifest of every scanned file. `guard` and
  `sandbox` re-hash immediately before running the command.

The walk never follows symbolic links, including ones swapped in while it
runs: directories are read through verified `/proc/self/fd` handles and every
opened file is checked against its earlier `lstat`. A relative symlink to a
file or directory inside the tree that the review covers (such as the
`LICENSES/0BSD.txt -> ../LICENSE` many AUR packages carry) is recorded by its
link text, so retargeting it changes the snapshot, and its target is reviewed
where it is. Other symlinks (absolute, leaving the tree, dangling, through
another link or into a skipped directory), special files,
non-UTF-8 file names, text files over 2 MiB, files over 512 MiB, unresolved
Git LFS pointers and an invalid or inconclusive AI reply all make the review
**incomplete**, never clear. An *unavailable* AI review (no OpenCode, a
provider error, a timeout) follows the class's `ai` setting instead: `WARNED`
for `official` under `standard`, blocked everywhere else. `.git` is always skipped; `target`,
`node_modules`, `.venv`, `vendor`, `dist` and `build` are skipped unless
`--thorough` is given.

External helpers are run by absolute path (`/usr/bin/curl`, `/usr/bin/bsdtar`,
`/usr/bin/pacman`, ...) with a timeout and bounded output. OpenCode is looked
up in the absolute entries of `PATH` for `scan`, `guard` and `sandbox`. The
pacman hook only accepts a root-owned `/usr/bin/opencode` or
`/usr/local/bin/opencode`, because it gates a root transaction and a
user-writable reviewer could be replaced by user-level malware. OpenCode must
be configured with a working provider; source leaves the machine through that
provider.

## Using Claude Code as the reviewer

A model written `claude-code/<model>` runs the review through the Claude Code
CLI (`claude`) instead of OpenCode, with your existing Claude login:

```toml
[agent]
model = "claude-code/claude-sonnet-5-5"
```

(or pick it in `omarchy-guardian tui` or `setup`, which list the Claude Code
models when `claude` is installed and suggest `claude-code/claude-sonnet-5-5`). Guardian runs `claude --print` with every
built-in tool disabled (`--tools ""`), no MCP servers (`--strict-mcp-config`),
no user, project or local settings, hooks or plugins (`--setting-sources ""`),
no slash commands and no saved session, from an empty private working
directory; the request goes on stdin, and the reply is read as a
`stream-json` transcript. A `tool_use` block in any assistant message, or a
permission denial, counts as a tool attempt and makes the review invalid;
the extra turn the CLI adds to continue a reply its safety classifier
interrupted does not. The reply must echo the nonce like OpenCode's. `thinking`
becomes `--effort` directly.

For your own sources `claude` is found on `PATH`. The pacman gate, as with
OpenCode, only accepts a root-owned `/usr/bin/claude` or
`/usr/local/bin/claude`; a Claude Code installed in your home directory is
not used for it, and `pacman-hook --preflight` says so.

## Install (Arch Linux / Omarchy)

```sh
cd packaging/arch
makepkg -si
sudo pacman -S --needed claude-code         # the pacman gate's reviewer (or extra/opencode)
sudo /usr/lib/omarchy-guardian/enable-system-hook.sh
yay --makepkg /usr/lib/omarchy-guardian/guardian-makepkg --save -P --stats
```

Or open `omarchy-guardian tui` and choose *Protect everything*, which does the
same after showing each step.

Installing the package activates nothing. `enable-system-hook.sh` links the
pacman hook into `/etc/pacman.d/hooks/` and adds the theme interceptor to the
invoking user's `~/.bashrc`.

The pacman hook refuses every transaction it cannot review. While any pacman
class requires the AI review (`third-party-repo` and `local-package` under
`standard`; every class under `strict`), that needs a root-owned reviewer
for the configured model (`/usr/bin/claude` from `claude-code` for a
`claude-code/` model, otherwise `/usr/bin/opencode`): one installed in your
home directory (for example with `mise` or `npm`) is not accepted. Without one, every `pacman -U` would be refused, including
each AUR package yay installs. `enable-system-hook.sh` therefore runs
`omarchy-guardian pacman-hook --preflight` as the invoking user first and does
not enable the hook until it passes. The pacman hook reviews as the invoking
user, with that user's Claude login or OpenCode configuration and credentials.

### Pacman hook

A pre-transaction hook (`AbortOnFail`) that reviews, for the exact archives
being installed, their `.INSTALL` scriptlets and the payload files that run or
grant privileges on their own:

- pacman hooks (`usr/share/libalpm/hooks`, `etc/pacman.d/hooks`), sudoers,
  polkit and PAM rules, `ld.so.preload` and `ld.so.conf.d`;
- systemd units a package enables itself (`*.wants/`, `*.requires/`,
  `*.upholds/`), generators and presets, and units in `etc/systemd`;
- tmpfiles, sysusers, binfmt, udev, modprobe and environment.d entries;
- login scripts (`etc/profile.d`, xinitrc.d), autostart entries, cron jobs and
  D-Bus system services and policies.

On an upgrade, an auto-run file identical to the installed one is not reviewed
again, since it adds nothing new: a point release typically brings a handful of
changed files, not every unit and rule. These files go to the AI review only;
the local pattern rules are written for scripts and would match the ordinary
content of these files. Binaries among them (generators, for example) are
listed as not reviewed. The rest of the payload is not reviewed.

Archives are located as follows:

- For `pacman -S`, each target's sync-database version (`pacman -Si`) is
  located in the configured `CacheDir`s (`pacman-conf`), and each archive's
  package name is confirmed with `pacman -Qqp`.
- For `pacman -U`, the archives named on pacman's command line are used,
  resolved against pacman's own working directory. Remote URLs are refused.

The AI review is told what is under review (the scriptlets and those payload
files) and what routine packaging looks like: capabilities or setuid on the
package's own files, system users, copying its own files into place, its own
services, sockets and device rules, and privileges that only apply once an
administrator opts in (a dedicated, initially empty group, or a boot
credential). Files a scriptlet only mentions, and how the package's own
programs authorize requests, are out of scope and not grounds for an
inconclusive verdict. It still flags downloading or running code from
elsewhere, sudoers, polkit or PAM rules that grant root broadly or without
authentication, pacman hooks or login and autostart scripts that run unrelated
code, preloaded libraries, persistence the package does not own, and access to
users' home directories or credentials. An inconclusive verdict blocks in
every profile, since ambiguity is something an attacker can provoke.

libalpm runs hooks as children of pacman after `chroot` + `chdir("/")`, so the
hook reads pacman's exact argv from `/proc/<pid>/cmdline` and its working
directory from `/proc/<pid>/cwd`, then drops to the invoking user (`sudo` or
`doas`) for the review. Transactions it cannot attribute to pacman, to an
invoking user, or to an archive are blocked. Front ends that call libalpm
directly (for example pamac) are not supported and will be blocked.

### yay makepkg gate

The yay shim runs `omarchy-guardian makepkg-gate` in the AUR build directory
before every `makepkg` call. yay calls makepkg several times per package; the
gate does, in order:

1. **AUR trust signals.** The package is looked up in the AUR RPC (only its
   name is sent): its age, votes, maintainer and submitter are printed, and a
   package first submitted under 30 days ago, with fewer than 5 votes,
   orphaned, or changed in the last 14 days by a maintainer who did not
   submit it is flagged. These are warnings, and are given to the AI review
   as facts.
2. **The recipe.** The PKGBUILD, install scripts, patches and other AUR files
   are reviewed as `guard --class aur --thorough --exclude src --exclude pkg`
   would. The AI is told that upstream sources are reviewed in the next
   step, that prebuilt binaries cannot be reviewed by anyone, and what
   routine packaging looks like. A PKGBUILD's `url=` and `source=` entries
   are declarations, not network requests, for the local rules, unless they
   run a command.
3. **Sources**, for a call that runs PKGBUILD functions (not
   `--verifysource`, `--packagelist`, `--nobuild --noprepare` and the like).
   Only now, with the recipe reviewed, `makepkg --printsrcinfo` lists the
   sources:
   - an unverified download over `http://` or `ftp://` blocks the build,
     since anyone on the network path can replace it;
   - a git (or other VCS) source not pinned to a commit, or an unverified
     download over HTTPS, is a warning.
4. **Upstream code.** If the call extracts the sources, the gate first
   fetches and extracts them itself with `makepkg --nobuild --noprepare
   --nodeps`, so no PKGBUILD function has run yet. The AI then reviews the
   upstream code under `src/`: all of it when its code is up to 1 MiB,
   otherwise its build files and scripts (makefiles, CMake, meson,
   `configure`, `setup.py`, `build.rs`, `package.json`, shell scripts…)
   first, then other code by depth, up to 1 MiB. Data and documentation
   (`.json`, `.md`, `.txt`…), version-control metadata, `node_modules` and
   CI or development-container directories are left out. The review looks
   for malicious intent in what runs during the build and in the program's
   own code, not bugs or vulnerabilities, and is told whether the recipe
   runs the test suite (`check()`). The upstream review is remembered as
   `aur-src:<package>`, so a new version is reviewed as a diff.
5. **makepkg** starts with the original arguments.

What is not reviewed is reported: how many code files were left out, and
that data files were skipped. Prebuilt binaries in `-bin` packages are not
reviewable.

### Omarchy themes

The theme & plugin gate routes theme installs and updates through Guardian from two
places: the Bash interceptor catches `omarchy theme install/update` typed in
an interactive Bash, and overrides in your Omarchy menu file
(`~/.config/omarchy/extensions/omarchy-menu.jsonc`) point Install › Style ›
Theme and Update › Extra Themes at Guardian, since the menu runs them in a
non-interactive shell the interceptor never sees. Turn both on from the TUI's
Integrations tab (or *Protect everything*); the gate shows as partial while
only one is in place. Themes are cloned to a hidden staging directory and
reviewed; only the exact reviewed checkout is moved into place and applied.
Updates stage and review every Git-installed theme before replacing any.
Themes with local or ignored modifications, submodules, or unresolved Git LFS
files are refused. Direct invocations of Omarchy's theme binaries from
elsewhere (scripts, other shells) are not intercepted.

### Omarchy plugins

Omarchy shell plugins run as unsandboxed code inside the long-lived
`omarchy-shell`, so `omarchy plugin add` (or `install`) and `omarchy plugin
update` go through `guardian-plugin`:

- **Add:** the repository is cloned to a hidden staging directory and checked
  with Omarchy's own `omarchy-plugin-validate`. It is then reviewed with
  `guard --class plugin --identity plugin:<id>`, and only after a clear review
  is the exact reviewed checkout moved into place and, if asked, enabled.
- **Update:** each installed plugin's new commits are fetched into a staged
  copy, fast-forwarded and validated, then reviewed as an upgrade of the
  approved version. The installed plugin is fast-forwarded to exactly the
  reviewed commit, taken from the staged copy rather than fetched from the
  remote again, so a push between review and apply is never installed.
  Plugins with local changes, rewritten remote history or submodules are
  refused.

Both routes are gated: the Bash interceptor catches the commands in an
interactive Bash, and the theme & plugin gate's menu overrides point Setup ›
Plugins › Add Plugin at Guardian. `omarchy plugin clone` copies Omarchy's own
built-in plugins and is not gated.

### Removal

```sh
yay --makepkg /usr/bin/makepkg --save -P --stats
sudo pacman -R omarchy-guardian
```

Removing the package removes the hook link. A hook at the same path that was
installed by hand and runs Guardian is moved to
`/etc/pacman.d/hooks/omarchy-guardian.hook.pacsave`, which pacman ignores.
Turn the theme & plugin gate off in the TUI (or delete the marked Guardian line from
`~/.bashrc` and the `guardian-theme` and `guardian-plugin` lines from the Omarchy
menu file) to stop theme and plugin interception.

If pacman fails every install or upgrade with `Review package install scripts
with Omarchy Guardian` followed by `call to execv failed (No such file or
directory)`, a Guardian hook is still active but the program it runs is gone,
typically after a manual install. pacman runs the hook before any package
script, so no install or removal can fix it; remove the hook first:

```sh
sudo rm /etc/pacman.d/hooks/omarchy-guardian.hook
```

## Limitations

A clean result only means the static checks, the configured AI provider and
the available OSV data did not identify a problem in the files reviewed.
Guardian can miss malicious behaviour and benign code can match a rule. It does
not inspect compiled package payloads, cannot prove an installed binary was
built from the reviewed source, and does not intercept direct downloads or
`curl | sh`. The sandbox is optional and limited to a 120 s run.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

On a non-Linux workstation, check with
`cargo clippy --target x86_64-unknown-linux-gnu --all-targets -- -D warnings`
(the crate refuses to build for other systems). Local hooks run the same
checks: `prek install` (see `.pre-commit-config.yaml`). CI builds and tests on
an Arch Linux container.

The integration gates (pacman hook, yay shim, theme install and update) have an
end-to-end harness that runs the real scripts in a Bubblewrap sandbox with a
throwaway `/usr` overlay, mock `makepkg`/`omarchy-theme-set`, a simulated pacman
parent process and a throwaway `HOME`:

```sh
cargo build --release
bash tests/e2e/integration-gates.sh
```

It needs `bwrap` 0.9 or newer, `bsdtar`, `pacman`, `git`, `flock`, `curl` and a
working `opencode`; it exits `77` when OpenCode cannot run, because every gate
is fail-closed on a failed AI review. To review with the Claude Code CLI and
your Claude login instead, set
`GUARDIAN_E2E_MODEL=claude-code/claude-sonnet-5-5` (the pacman checks that need
the AI are then skipped, because the pacman gate takes its model only from a
root-owned system config).

The AI review itself has an evaluation suite: install scriptlets, auto-run
package files and AUR recipes that must come back clear, and attacks that must
be caught. Run it after changing a prompt, a scope or the model:

```sh
cargo build --release
RUNS=3 bash tests/ai-eval/run.sh          # or a filter: run.sh aur/block
```

Every run starts with an empty review memory, so no verdict comes from the
cache. The pacman cases use the system config's model, the AUR cases the user
config's.
