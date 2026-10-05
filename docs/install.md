# Install, upgrade and removal

Everything about installing: what `./install.sh` does, how an installed Guardian
verifies and installs the next release, how to verify a release by hand, the
same steps without the installer, what `omarchy-guardian protect` turns on,
how to remove Guardian, and what to do when a leftover hook stops pacman.

## Contents

- [Requirements](#requirements)
- [Install](#install)
- [Upgrading](#upgrading)
- [Hearing of a new release](#hearing-of-a-new-release)
- [Verifying a release](#verifying-a-release)
- [Installing by hand](#installing-by-hand)
- [Turning protection on](#turning-protection-on)
- [Removal](#removal)
- [If pacman fails every install](#if-pacman-fails-every-install)

## Requirements

Guardian runs on Arch Linux and Omarchy (`x86_64` and `aarch64`). The
package's own dependencies (`bubblewrap`, `coreutils`, `curl`, `git`, `glibc`,
`jq`, `libarchive`, `pacman`, `util-linux`) are installed by pacman with it.
Besides those:

- `base-devel` and a Rust toolchain, 1.88 or newer (`cargo`), to build it;
  Arch's `rust` or rustup's `stable` both work;
- an AI reviewer: `claude-code` (what the installer offers and `setup`
  suggests; it is in Omarchy's repository, not in Arch's) or `extra/opencode`
  with a working provider. With no model set, reviews go through OpenCode and
  its default model. The pacman gate only runs a root-owned one, as those
  packages install it (see [below](#how-the-pacman-hook-is-turned-on));
- `sudo`, for the steps that need root;
- `openssh` (`ssh-keygen`): needed by `/usr/lib/omarchy-guardian/upgrade`,
  which will not run without it, and by the installer's signature check;
- optional: `yay` (the AUR gate guards nothing without it), `libnotify` for
  desktop notifications, and `gum` for the theme and plugin gates' questions.

## Install

```sh
git clone https://github.com/gosumarchy/omarchy-guardian
cd omarchy-guardian
./install.sh
```

The installer checks for a Rust toolchain (rustup's `cargo` is fine), builds
and tests the package, installs it with pacman, makes sure there is an AI
reviewer (it offers `claude-code`, or `extra/opencode` where no repository
has that package), runs the guided setup on a first install, turns every gate
on with `omarchy-guardian protect` after showing each step, and tests the
reviewer with a malicious and a harmless sample. If it has to install the
reviewer, it stops there: log in once (run `claude`, or set up a provider in
`opencode`), then run the installer again. It asks for sudo only for the steps
that need it, and skips what is already done: when the version of this
checkout is the one already installed, it does not build or install again and
goes on with the reviewer, the settings and `protect`.
`./install.sh --reinstall` builds and installs it anyway (after changing the
source without a new version, say). With the pacman hook on, the installed
Guardian reviews the new package like any other local archive before pacman
installs it.

## Upgrading

An installed Guardian from 0.8.0 on carries the release keys and its own
upgrade check. Upgrade with:

```sh
git pull && /usr/lib/omarchy-guardian/upgrade
```

For a first install, and while the installed Guardian is older than 0.8.0 (it
has no release keys and no upgrade check), it is `git pull && ./install.sh`,
with the tag checked by hand as shown under [Verifying a
release](#verifying-a-release). The installer's last line says which of the
two applies.

`/usr/lib/omarchy-guardian/upgrade` is part of the installed package
(root-owned, and a path the pacman gate protects), not of the checkout, and it
treats the checkout as data it does not trust:

- It reads the object id of the release tag from the checkout's `.git` as
  text, and the checkout's objects as files. No git command runs with the
  checkout as its repository, so nothing the checkout configures is used: not
  `.git/config` (a verifying program, hooks, `core.worktree`,
  `core.fsmonitor`, included files), not its index, not its hooks, replace
  refs or attributes.
- It copies the tag, its commit and that commit's files into a fresh
  repository of its own. Every object's id is computed again from its content
  on the way, so an object file that is not what its name says does not
  arrive.
- There it verifies the tag's SSH signature by object id, with
  `/usr/bin/ssh-keygen`, against
  `/usr/share/omarchy-guardian/allowed_signers`, and requires a tag object
  (not a plain tag) that carries the name it is stored under: the genuine
  signed tag of an old release stored as `v9.9.9` is refused. It prints the
  tag, the commit, the signer and the key's fingerprint.
- It exports exactly the signed tree into an empty private directory under
  `~/.cache/omarchy-guardian/` and builds there. Nothing of the checkout's
  working tree is used: no changed or added file, no build output left behind.
  The directory is removed when the installer returns (`--keep` keeps it).
- It refuses a release older than the installed one: an old release with a
  hole that a later one closed is signed too. `--allow-downgrade` overrides
  that.
- Then it starts the exported release's own `install.sh`, which is signed
  content, and passes `--yes` and `--reinstall` on to it.

### Options

`upgrade [checkout [tag]]` takes the checkout's directory (default: the
current one) and a tag (default: the highest `vX.Y.Z` tag that verifies; a tag
that does not is named and passed over). `upgrade --check` verifies and
exports without building; the export is removed again unless `--keep` is
given. It runs as your user and refuses to run as root.
When the installed Guardian carries no release keys it says so and builds
nothing.

### What the upgrade check relies on

The upgrade check relies on the installed Guardian and its key list (protected
by root ownership and by the pacman gate), on `git`, `ssh-keygen` and `tar`
from the system, and on the release key itself. What it cannot know: a
release newer than the newest tag your checkout has (someone who controls
where you pull from can withhold a release, though not forge one), and whether
a first install was genuine.

## Hearing of a new release

From 0.8.3 on Guardian tells you when a release newer than the installed one
is out. It only tells: nothing is downloaded to be run and nothing is
installed. Upgrading stays your own step, through the upgrade check above.

- **When it asks.** At the end of each scheduled [system
  sweep](system-sweep.md#on-a-schedule), so once a day and only while the
  sweep is turned on. `omarchy-guardian update` asks at once, says what is
  installed and what is newest, and prints the upgrade command.
- **What it asks.** One HTTPS request with `curl` to the project's repository
  on GitHub for its list of branches and tags, the request `git` itself makes
  first. Nothing about your machine goes with it, not even the installed
  version; GitHub sees your address and that the list was asked for.
- **What it does with the answer.** Of every tag only
  `v<number>.<number>.<number>` counts, and the newest is kept as three
  numbers in `update.json` in your state directory
  (`~/.local/state/omarchy-guardian`). What is shown is written again from
  those numbers, never text from the answer.
- **What you see.** One notification per release ("Guardian 0.8.4 is
  available"), and from then until you upgrade a line in the bar's tooltip or
  panel and an `update` member in `omarchy-guardian status`. It is not counted
  as a problem: the knight stays calm.
- **When it cannot ask.** Offline, or GitHub not answering: nothing is said
  and the next sweep asks again. `omarchy-guardian update` exits 2 and says
  why.

To turn it off, in either settings file (see [Settings
files](settings.md#settings-files)):

```toml
[update]
check = "off"
```

Off in either file is off: no request is made by the sweep and the bar says
nothing. `omarchy-guardian update` still asks when you type it.

What this does not give you:

- The list of tags is not signed, so the notice is a hint and no proof. A tag
  that should not be there costs you a notification; `upgrade` then refuses a
  release whose tag is not signed with the project's key.
- Whoever can keep the answer from you (your network, GitHub) can keep you
  from hearing of a release. Nothing here notices a notice that never came.
- The record is your own file: a program running as you can rewrite it, or
  turn the check off in your settings file, and so keep the notice quiet.

## Verifying a release

Guardian's hook runs as root inside pacman, so what you build matters.
Releases are annotated git tags (`vX.Y.Z`); from 0.8.0 on, the release that
added the key file `packaging/allowed_signers`, they are signed with an SSH
key listed there. For a first install, or while the installed Guardian has no
keys, check out a tag rather than the tip of a branch and check its signature
by hand, against a key file you have reason to trust (one you compared with
the key the maintainer publishes):

```sh
git fetch --tags && git checkout vX.Y.Z
git -c gpg.format=ssh \
    -c gpg.ssh.allowedSignersFile=/path/to/allowed_signers \
    verify-tag refs/tags/vX.Y.Z
git status --short --ignored      # nothing changed, nothing added
./install.sh
```

Do this in a clone you made yourself. `git verify-tag` runs in the checkout
and believes its `.git/config`, so it proves nothing about a checkout someone
else prepared; and the key file in the checkout itself
(`packaging/allowed_signers`) proves nothing about that checkout. A first
install is trust on first use: nothing on the system can vouch for it yet.

### What the installer checks

`./install.sh` also checks what it is about to build, and says what it found.
That check is part of the checkout it checks, so it guards against mistakes,
not against tampering: someone who changed the checkout could have changed the
installer too. With installed keys it says so and names the upgrade check
above.

What it does: with installed keys it asks before going on unless `HEAD` is the
commit of a release tag signed by an installed key and the working tree is
exactly that commit's tree. The tag is looked up as `refs/tags/<name>` and
verified by object id, has to be a tag object that names `HEAD`'s commit and
carries its own name, and git is run with the verifying program, the signature
format, the keys file and the working tree given on its command line and
without the system's or your own git configuration.

Every file of the tagged tree is hashed from disk and compared (content,
executable bit, links), without asking the index, so a file the index was told
to pass over is still compared; and every file on disk that is not in the
tagged tree counts (cargo would run an added `build.rs` or
`.cargo/config.toml`, and an added `packaging/allowed_signers` would be
installed as the keys the next upgrade is checked against), whatever the index
or `.git/info/exclude` say. Only what the tag's own top-level `.gitignore`
names, the build's output, is passed over, and the build starts from an empty
build directory (`makepkg --cleanbuild`), so what is passed over is not linked
in.

A directory that is not a git checkout (an unpacked tarball), or whose `.git`
is a file (a linked worktree), cannot be checked. With installed keys that is
asked about too, and `--yes` never answers the question. Without installed
keys (every first install) the installer says what it found and that the
signature was not checked, and goes on. A package built from a release that
ships no key file installs none.

How to report a weakness, and what counts as one, is in
[SECURITY.md](../SECURITY.md).

## Installing by hand

By hand, the same steps are:

```sh
cd packaging/arch
makepkg -fd                                   # -d: rustup's cargo is not a pacman package
sudo pacman -U "$(makepkg --packagelist | grep -v -- '-debug-' | head -n 1)"
sudo pacman -S --needed claude-code           # the pacman gate's reviewer (plain Arch: extra/opencode)
omarchy-guardian setup
omarchy-guardian protect                      # or: omarchy-guardian tui › Protect everything
```

## Turning protection on

`omarchy-guardian protect` turns on the pacman hook, the yay AUR gate, the
theme and plugin gate, the theme and plugin commands on the session's PATH,
the Omarchy menu entry, the bar widget (Waybar and/or Omarchy's shell bar) and
the daily [system sweep](system-sweep.md), showing each step and asking first
(`--yes` skips the question, but never answers whether the sweep's root checks
may run); `protect --off` turns the pacman hook, the AUR gate, the theme and
plugin gate, the commands on PATH and the system sweep off the same way (the
menu entry and the bar widget stay, and a pacman hook installed by hand is
left alone). The commands on PATH take effect from the next login. When the
pacman gate could not review with the current settings, `protect` leaves the
pacman hook off and says why; if what is missing is a root-owned OpenCode, it
offers to install `extra/opencode` as one of its steps instead.
`omarchy-guardian test` runs the two-sample reviewer test from the terminal.

### How the pacman hook is turned on

Installing the package activates nothing. The package ships its hook in
libalpm's own hook directory (`/usr/share/libalpm/hooks/`), which pacman reads
whatever `--hookdir` it is given, but the hook lets every transaction through
until root has turned it on. `protect` (and the settings app) link the hook
into `/etc/pacman.d/hooks/` with `sudo`; by hand, `sudo
/usr/lib/omarchy-guardian/enable-system-hook.sh` does the same and also adds
the theme interceptor to the invoking user's `~/.bashrc`. The link is what
turns the hook on; a hook of the same name there takes the place of the
packaged one, so it still runs once.

The pacman hook refuses every transaction it cannot review. While any pacman
class requires the AI review (`third-party-repo` and `local-package` under
`standard`; every class under `strict`), that needs a root-owned reviewer for
the configured model (`/usr/bin/claude` or `/usr/local/bin/claude` for a
`claude-code/` model, otherwise `/usr/bin/opencode` or
`/usr/local/bin/opencode`): one installed in your home directory (for example
with `mise` or `npm`) is not accepted. Without one, every `pacman -U` would be
refused, including each AUR package yay installs. `protect` therefore checks
first that the gate can review and does not enable the hook until it can;
`omarchy-guardian pacman-hook --preflight` does the same check by hand, and
`enable-system-hook.sh` runs it as the invoking user. The pacman hook reviews
as the invoking user, with that user's Claude login or OpenCode credentials
(not that user's OpenCode configuration, which the pacman gate leaves out).

## Removal

```sh
omarchy-guardian protect --off     # the gates, the commands on PATH, the sweep's timers
sudo pacman -R omarchy-guardian
```

`protect --off` removes the hook link, points yay back at `makepkg`, takes the
Guardian line out of `~/.bashrc` and the theme and plugin entries out of the
Omarchy menu file, removes `~/.config/uwsm/env.d/90-omarchy-guardian` and
Guardian's line from `~/.config/hypr/hyprland.lua`, and turns the sweep's two
timers off, showing each step first. It leaves the menu entry and the bar
widget (remove those in the settings app's Integrations tab, before removing
the package) and a pacman hook that was installed by hand. With the link gone
the packaged hook lets every transaction through, so this alone turns the
pacman gate off without removing the package.

Removing the package removes the hook link if it is still there, turns the
root checks' timer off, and takes the hook in `/usr/share/libalpm/hooks/` with
the package's files. A hook at the link's path that was installed by hand and
runs Guardian is moved to `/etc/pacman.d/hooks/omarchy-guardian.hook.pacsave`,
which pacman ignores. A removal is not reviewed by the gate.

If you removed the package without `protect --off`, undo the rest by hand:
`yay --makepkg /usr/bin/makepkg --save -P --stats`, delete the two Guardian
lines (the marker comment and the `source` line) from `~/.bashrc`, the
`guardian-theme` and `guardian-plugin` lines from the Omarchy menu file,
`~/.config/uwsm/env.d/90-omarchy-guardian` (left behind, it only names a
directory that no longer exists) and the two Guardian lines at the end of
`~/.config/hypr/hyprland.lua` (left behind, the line passes over its missing
file), and `systemctl --user disable omarchy-guardian-sweep.timer`. Until then
yay fails on the missing shim and the menu's theme and plugin items name a
handler that is gone; the line in `~/.bashrc` loads nothing once its file is
gone.

If the menu entry and the bar widget were still there, remove them by hand
too: the `"setup.guardian"` line in
`~/.config/omarchy/extensions/omarchy-menu.jsonc`, the
`"image#omarchy-guardian"` lines in the Waybar config and the block between
`/* Omarchy Guardian: begin */` and `/* Omarchy Guardian: end */` in its
`style.css`, and the directory `~/.config/omarchy/plugins/omarchy-guardian`.

Not removed with the package, since they are yours or root's own records: the
settings (`/etc/omarchy-guardian/`, `~/.config/omarchy-guardian/`), the list
of allowed sweep items and the root checks' last results
(`/var/lib/omarchy-guardian/`), the review memory
(`~/.local/state/omarchy-guardian/`) and the saved reports
(`~/.cache/omarchy-guardian/`). The `<name>.guardian-bak` copies beside
`~/.bashrc`, the menu file, `hyprland.lua` and the Waybar config are the files
as they were before Guardian's first edit; delete them when you no longer want
them.

## If pacman fails every install

If pacman fails every install or upgrade with `Review package install scripts
with Omarchy Guardian` followed by `call to execv failed (No such file or
directory)`, a Guardian hook is still active but the program it runs is gone,
typically after a manual install. pacman runs the hook before any package
script, so no install or removal can fix it; remove the hook first:

```sh
sudo rm /etc/pacman.d/hooks/omarchy-guardian.hook
```
