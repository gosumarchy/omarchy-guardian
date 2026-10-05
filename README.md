# Omarchy Guardian

[![CI](https://github.com/gosumarchy/omarchy-guardian/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gosumarchy/omarchy-guardian/actions/workflows/ci.yml)

Omarchy Guardian reviews what pacman packages, AUR builds, and Omarchy themes
and plugins would run on your machine, before any of it runs, and audits what
already runs there on its own. It is for Arch Linux and Omarchy. It is an
early, heuristic tool: a clear result is not a safety guarantee.

It is a single Rust binary with **no third-party crates**. SHA-256, JSON, and
the small subset of TOML it needs are implemented in the crate so the whole
gate can be audited in one place. It builds only for Linux.

## What it needs, sends and changes

- **An AI reviewer of your own.** Reviews run through the Claude Code CLI with
  your Claude login, or through OpenCode with the provider you set up there.
  Guardian has no service of its own.
- **Code leaves the machine.** The text under review is sent to that provider:
  package install scriptlets and auto-run files, AUR recipes and their
  sources, themes, plugins, what you `scan`, and for the daily sweep the
  start-up files on this machine that no package vouches for, with the
  scripts they run. A file whose name or path marks it as holding keys or
  tokens (`.env`, `*.pem`, `*.key`, `id_ed25519`, anything under `.ssh` or
  `secrets`, and the like) is not sent, by any gate or by the sweep, whatever
  runs it. In a gate the review is then incomplete, not clear. In the sweep
  such a file is read by the local rules, looked through for what it starts,
  and listed as kept from the AI; where something runs it, that is a finding
  of its own. The sweep also checks SSH and git files in a
  home, package-manager configuration and account files locally only, sends a
  file it found running only where it is plainly a script, and takes plainly
  written secret values and URL passwords out of what it sends. A secret
  anywhere else goes with its file. Package names and
  versions from lockfiles go to the OSV API (`api.osv.dev`), and an AUR
  package's name goes to the AUR. The `local-only` level sends nothing to an
  AI; the OSV and AUR lookups remain.
- **Each review is one or more AI calls** on your subscription or API account:
  by default up to 8 calls of up to 256 KiB each. System updates with
  scriptlets, every AUR build and the daily sweep all make calls. Unchanged
  sources are answered from a cache, except pacman packages.
- **`protect` changes your system**, showing each step first: a link in
  `/etc/pacman.d/hooks/`, yay's saved configuration, a line in `~/.bashrc`,
  entries in the Omarchy menu file, `~/.config/uwsm/env.d/90-omarchy-guardian`
  and two lines in `~/.config/hypr/hyprland.lua` (from the next login), a bar
  widget or Waybar module, and the sweep's systemd timers. Edited files are
  kept beside themselves as `<name>.guardian-bak`. `omarchy-guardian protect
  --off` undoes the gates; see [Removal](#removal).

## How protection works

Guardian sits in front of the ways Omarchy installs packages, themes and
plugins, and reviews what would run on install **before any of it runs**:

```text
 pacman -S / -U / -Syu ──► pacman hook ─────► install scriptlets + auto-run files
 yay (AUR)             ──► makepkg gate ────► PKGBUILD, then the upstream sources
 omarchy theme install ──► theme gate ──────► the theme checkout
 omarchy plugin add    ──► plugin gate ─────► the plugin checkout
                                  │
                   local rules + AI review (Claude Code or OpenCode)
                                  │
             clear ─► the install goes ahead
             risk  ─► blocked, full report in the terminal + desktop notification

 what already runs on its own ──► daily system sweep ──► new or changed items
```

- **Two reviews.** Fast local rules flag known-bad patterns. An AI reviewer
  then reads the code with every tool switched off and must echo a one-time
  nonce given after the code. The code can still try to talk the reviewer into
  a clean verdict, which is one reason the local rules always run too and a
  clear result is not a guarantee. See [Review](docs/review.md) and [Local
  rules](docs/local-rules.md).
- **Pacman packages.** For the exact archives being installed, Guardian
  reviews the install scriptlets, the files that run or grant privileges on
  their own (hooks, units, sudoers and the like), and the package's text files
  that those refer to. The rest of the payload is not reviewed. See [Pacman
  gate](docs/pacman-gate.md).
- **AUR builds.** The recipe (PKGBUILD) is reviewed before any of it runs. Its
  sources are then listed in a sandbox with no network, fetched without
  running any code of the package, and reviewed before anything is built. The
  one exception is yay's own download-and-verify call, where the reviewed
  recipe and its `verify()` run as you. Prebuilt programs, and a recipe whose
  sources Guardian cannot follow, are not waved through: Guardian says so and
  asks on the terminal. See [AUR gate](docs/aur-gate.md).
- **Themes and plugins.** Omarchy theme and plugin installs and updates are
  staged and reviewed, and only the exact reviewed checkout is moved into
  place. See [Themes and plugins](docs/themes-and-plugins.md).
- **Fail closed.** A review that cannot finish blocks. An unavailable AI
  blocks community sources; for official Arch/Omarchy updates the `standard`
  profile warns instead, `strict` blocks. A question nobody can be asked (no
  terminal) is answered no. A settings file that does not parse stops the
  gates that read it instead of being skipped. See
  [Settings](docs/settings.md).
- **Blocks you can read.** A block prints the full report in the terminal and
  raises a desktop notification that opens it as a page, with a button to ask
  your AI agent about it. One blocked install can be let through with a
  permit, for exactly the content that was reviewed. See [After a
  block](docs/permits.md).
- **A daily system sweep.** `omarchy-guardian sweep` checks what already runs
  on its own on this machine and notifies about what is new or changed. See
  [System sweep](docs/system-sweep.md).
- **An audit trail.** Every decision goes into the system journal. See [What
  Guardian decided](docs/audit-trail.md).
- **A bar widget.** The Guardian knight sits in the bar: calm when every gate
  is on, red-eyed when something needs attention, dim when protection is off.
  See [The bar and `status`](docs/settings.md#the-bar-and-status).
- **A settings app.** The settings app (`omarchy-guardian tui`) turns
  every gate on with *Protect everything*, picks the protection level and the
  model, and tests the reviewer with a malicious and a harmless sample. See
  [Settings app](docs/settings.md#settings-app).

## Requirements

- Arch Linux or Omarchy, `x86_64` or `aarch64`. Guardian builds only for
  Linux.
- `base-devel` and a Rust toolchain, 1.88 or newer (`cargo`), to build it;
  Arch's `rust` or rustup's `stable` both work.
- An AI reviewer: Claude Code (`claude-code`, what the installer offers and
  `setup` suggests; it is in Omarchy's repository, not in Arch's) or OpenCode
  (`extra/opencode`) with a working provider. With no model set, reviews go
  through OpenCode and its default model. The pacman gate only runs a
  root-owned one, as those packages install it.
- `sudo`, for the steps that need root.
- `openssh` (`ssh-keygen`) for upgrades: the upgrade check will not run
  without it, and the installer cannot check a release's signature without it.
- Optional: `yay` for the AUR gate, `libnotify` for desktop notifications,
  `gum` for the theme and plugin gates' questions.

The package's other dependencies are installed by pacman with it; the list is
under [Install](docs/install.md#requirements).

## Install

```sh
git clone https://github.com/gosumarchy/omarchy-guardian
cd omarchy-guardian
./install.sh
```

The installer checks for a Rust toolchain, builds and tests the package,
installs it with pacman, makes sure there is an AI reviewer (it offers
`claude-code`), runs the guided setup on a first install, turns every gate on
with `omarchy-guardian protect` after showing each step, and tests the
reviewer with a malicious and a harmless sample. It asks for sudo only for the
steps that need it, and skips what is already done. If it has to install the
reviewer, it stops there: log in once (run `claude`, or set up a provider in
`opencode`), then run the installer again.

Installing the package alone activates nothing: `omarchy-guardian protect` (or
*Protect everything* in the settings app) turns the gates on. The steps by
hand, and what each does, are under [Install](docs/install.md).

A first install is trust on first use: nothing on the system can vouch for it
yet. To check the release tag by hand first, see [Verifying a
release](docs/install.md#verifying-a-release).

## Upgrade

```sh
git pull && /usr/lib/omarchy-guardian/upgrade
```

Releases are annotated git tags, signed from 0.8.0 on. The upgrade check is
part of the installed package, not of the checkout: it verifies the release
tag's signature against the keys the installed Guardian carries, builds
exactly the signed tree, and refuses a release older than the installed one.
See [Upgrading](docs/install.md#upgrading) and [Verifying a
release](docs/install.md#verifying-a-release).

An installed Guardian older than 0.8.0 has no release keys and no upgrade
check: there it is `git pull && ./install.sh`, with the tag checked by hand.

## Commands

| Command | What it does |
| --- | --- |
| `scan PATH` | reviews a file or directory and prints a report |
| `guard PATH -- COMMAND` | reviews, then runs the command only after a clear or warned review |
| `sandbox DIR -- COMMAND` | reviews, then runs the command on a copy, in a Bubblewrap sandbox |
| `sweep` | checks what already runs on its own on this machine |
| `permit [ID]` | lets one blocked install through, for exactly the reviewed content |
| `log` | shows what Guardian decided, from the system journal |
| `ask REPORT-ID` | opens your AI agent on a saved report, with every tool switched off |
| `status` | prints the gates, the problems and the last block as JSON, which the bar reads; `--dismiss` marks them seen, `--open-report` opens the last report |
| `tui` | opens the settings app (`--expert` for every setting) |
| `protect [--off] [--yes]` | turns every gate on, or the install gates and the sweep off |
| `setup` | guided setup: reviewer, profile, model, and a test review |
| `config …` | `show`, `check`, `path`, and `acknowledge` for weaker settings |
| `forget ID`, `forget --all` | drops a source's approved baselines, or the whole review memory |
| `test` | tests the reviewer with a malicious and a harmless sample |

Each is run as `omarchy-guardian COMMAND`. The options and the details are
under [Commands](docs/commands.md) and [Settings](docs/settings.md).

| Exit | Meaning |
| --- | --- |
| `0` | clear, warned, limited review or permitted |
| `1` | findings |
| `2` | no verdict: incomplete, AI unavailable, not confirmed, or an error |

A limited review is a scriptlet-free pacman transaction. Exit `2` covers an
incomplete review, an unavailable AI review under `ai = required`, a question
that got no yes (`NOT CONFIRMED`), a settings file that does not parse, and a
usage error.

`guard` and `sandbox` never exit `0` without having started the command; once
they start it, the exit code is the command's own. The full table is under
[Decisions and exit codes](docs/settings.md#decisions-and-exit-codes).

## After a block

A review can be wrong. When a gate blocks on something you may reasonably
overrule, its report ends with a permit line:

```sh
omarchy-guardian permit          # blocked installs waiting, and permits in force
omarchy-guardian permit ID       # show what is overruled, ask, store the permit
```

`permit ID` shows the decision and the content's SHA-256 again, asks you to
type `permit` on the terminal and then for the sudo password. Run the install
again and the gate lets exactly that content through, for 30 minutes. Some
blocks cannot be permitted (what a gate refuses rather than reviews, a
question you declined), and under the `strict` level permits are off. See
[After a block](docs/permits.md).

## What is not covered

A clean result only means the static checks, the configured AI provider and
the available OSV data did not identify a problem in the files reviewed.
Guardian can miss malicious behaviour and benign code can match a rule. The
limits are listed here. Each is stated in full on its page, and all of them
under [Limitations](docs/limitations.md):

- Programs you download and run yourself, and `curl | sh` pasted into a
  terminal, are not intercepted. `omarchy-guardian guard` and `sandbox` cover
  a download you start by hand
  ([Limitations](docs/limitations.md#not-covered-at-all)).
- Flatpak, npm, pip, mise and other language package managers are not covered
  ([Limitations](docs/limitations.md#not-covered-at-all)).
- Compiled programs are not inspected, and nothing proves an installed binary
  was built from the reviewed source
  ([Limitations](docs/limitations.md#what-a-clear-result-means)).
- Pacman packages: only scriptlets, auto-run files and the text files those
  name are reviewed, not the rest of the payload; a removal is not reviewed; a
  unit you enable yourself later is not reviewed then ([Pacman
  gate](docs/pacman-gate.md#what-the-gate-does-not-see)).
- Pacman: no hook can close the moment between the hook's exit and pacman
  opening an archive again ([Pacman
  gate](docs/pacman-gate.md#how-archives-are-located)).
- Pacman: front ends that call libalpm directly (pamac) are blocked, not
  reviewed ([Pacman gate](docs/pacman-gate.md#how-the-hook-runs)).
- AUR builds: yay's download-and-verify call runs the reviewed recipe and its
  `verify()` as you before the sources are reviewed ([AUR
  gate](docs/aur-gate.md#what-is-not-reviewed)).
- AUR builds: dependencies a build downloads itself (cargo crates, npm
  packages, Go modules, pip) are not reviewed ([AUR
  gate](docs/aur-gate.md#what-is-not-reviewed)).
- AUR builds: prebuilt programs cannot be reviewed by anyone; they are your
  decision, not a review ([AUR
  gate](docs/aur-gate.md#step-5-prebuilt-programs)).
- AUR builds: Guardian works out what a recipe will fetch by reading its text,
  and that reading is not a shell. The real makepkg loads the recipe again
  outside the sandbox and fetches what it says then ([AUR
  gate](docs/aur-gate.md#step-4-upstream-code)).
- AUR builds with the AI review off: the upstream sources are read only by the
  local rules' high checks ([AUR
  gate](docs/aur-gate.md#what-is-not-reviewed)).
- Themes and plugins: only installs and updates that reach Guardian's commands
  are reviewed. A caller that names Omarchy's command by its full path or
  resets `PATH`, a session not started through uwsm and Hyprland (it has the
  Bash interceptor only), and a theme or plugin copied into place by hand do
  not pass a gate ([Themes and
  plugins](docs/themes-and-plugins.md#not-covered)).
- The reviewer can be talked to: the reviewed text reaches the model and can
  address it, and the nonce cannot show how carefully the source was read
  ([Review](docs/review.md#what-is-checked)).
- The local rules read text, not meaning: a command assembled another way is
  left to the AI review ([Local rules](docs/local-rules.md)).
- Large sources and upgrades: a payload split over two files that land in
  different chunks is seen by no single request, and an upgrade review does
  not see what a change switches on in a file that is neither shown nor named
  ([Review](docs/review.md#how-the-review-scales)).
- A program already running as you can change what you own: the user settings
  file, the review memory, the records the bar and the sweep keep, the
  session's PATH file, and Guardian's lines in `hyprland.lua` and `~/.bashrc`.
  It can also write journal entries that look like Guardian's own
  ([Limitations](docs/limitations.md#the-limits-that-matter-most), [What
  Guardian
  decided](docs/audit-trail.md#what-an-entry-proves-and-what-it-does-not)).
- Root is trusted: the sweep judges files by pacman's own records, which root
  can rewrite, and the pacman gate reviews as the user who called `sudo`, with
  that user's reviewer login
  ([Limitations](docs/limitations.md#the-limits-that-matter-most)).
- System sweep: the EFI programs and the inside of the initramfs image are
  not looked at, and other mounted filesystems are not searched for setuid
  files; as a user only your own processes can be looked at; without root
  checks every sweep is incomplete ([System sweep](docs/system-sweep.md)).
- Source leaves the machine through the AI provider you configured, except
  under `local-only` and except the files kept from the AI by name or kind; a
  secret under a name Guardian does not recognise still goes with its file.
  Under `local-only` no source is sent, but lockfile package names and
  versions still go to the OSV API and an AUR package's name to the AUR
  ([Limitations](docs/limitations.md#the-limits-that-matter-most), [System
  sweep](docs/system-sweep.md#what-goes-to-the-review)).
- A block's report is passed to your AI agent on its command line, which other
  local users can read ([After a block](docs/permits.md#the-report)).
- `sandbox` is optional and limited to a 120 s run: a behaviour smoke test,
  not a dynamic malware detector ([Commands](docs/commands.md)).
- Releases: a first install cannot check the release signature, and someone
  who controls where you pull from can withhold a newer release, though not
  forge one ([Install](docs/install.md#verifying-a-release)).

## Removal

```sh
omarchy-guardian protect --off     # the gates, the commands on PATH, the sweep's timers
sudo pacman -R omarchy-guardian
```

`protect --off` undoes what `protect` turned on, showing each step first;
removing the package takes the hook with it. Your settings, the review memory
and the saved reports are left where they are. What to undo by hand when the
package was removed first, and how to recover when pacman fails every install
with a leftover hook, is under [Removal](docs/install.md#removal).

## Documentation

- [Install, upgrade and removal](docs/install.md): the installer, the upgrade
  check, verifying a release, `protect`, and removal.
- [Commands](docs/commands.md): `scan`, `guard`, `sandbox`, `sweep`, `permit`,
  `log`, and the exit codes.
- [Pacman gate](docs/pacman-gate.md): what the pacman hook reviews, what it
  refuses, and what it does not see.
- [AUR gate](docs/aur-gate.md): the makepkg gate's steps for a yay build, and
  what is not reviewed.
- [Themes and plugins](docs/themes-and-plugins.md): the commands on PATH, the
  Bash interceptor and the menu overrides.
- [System sweep](docs/system-sweep.md): what already runs on its own, how each
  item is judged, the root checks and the daily timers.
- [Review](docs/review.md): the AI review, how the reviewer is run, large
  sources, upgrades and the review memory.
- [Local rules](docs/local-rules.md): the pattern rules, network destinations
  and the dependency audit.
- [Settings, profiles and status](docs/settings.md): the settings app, the
  bar, source classes, profiles, the settings files, decisions and exit codes.
- [After a block](docs/permits.md): the report, and permits for one blocked
  install.
- [What Guardian decided](docs/audit-trail.md): the audit trail in the system
  journal.
- [Limitations](docs/limitations.md): what a clear result means, and what is
  not covered.
- [Development](docs/development.md): checks, test suites, measuring the AI
  review, and cutting a release.

## Security

How to report a weakness, what counts as one, and how releases are verified is
in [SECURITY.md](SECURITY.md).

## Development

`cargo fmt`, `cargo clippy` and `cargo test`, four end-to-end suites and the
release steps are described under [Development](docs/development.md).

## Licence

MIT; see [LICENSE](LICENSE).
