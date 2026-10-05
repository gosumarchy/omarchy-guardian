# Pacman gate

The pacman gate reviews what a pacman transaction would run or grant on its
own, before pacman installs anything. Its mechanism is the pacman hook: a
pre-transaction hook that stops the transaction when the review does not pass.
This page lists what is reviewed, what is refused outright, how the archives
are found and held to the reviewed bytes, and what the gate does not see.
Turning the hook on is described under
[Install](install.md#how-the-pacman-hook-is-turned-on).

## Contents

- [What counts as auto-run](#what-counts-as-auto-run)
- [What is reviewed](#what-is-reviewed)
- [Files the reviewed files name](#files-the-reviewed-files-name)
- [Rights a package hands out, and refused paths](#rights-a-package-hands-out-and-refused-paths)
- [Symbolic links](#symbolic-links)
- [What the gate does not see](#what-the-gate-does-not-see)
- [Upgrades](#upgrades)
- [How archives are located](#how-archives-are-located)
- [Guardian's own package and the reviewer's](#guardians-own-package-and-the-reviewers)
- [What the AI review is told](#what-the-ai-review-is-told)
- [How the hook runs](#how-the-hook-runs)

## What counts as auto-run

For pacman packages, auto-run means the install scriptlet, the files that run
without you starting them (pacman hooks, enabled systemd units, sudoers,
polkit, PAM, udev, tmpfiles, profile scripts, autostart entries; the full list
is under [What is reviewed](#what-is-reviewed)), and the package's own text
files those name. Unchanged files are skipped on upgrade. The
[system sweep](system-sweep.md) reads the same locations on the installed
system, and more: the places listed under
[Rights a package hands out](#rights-a-package-hands-out-and-refused-paths)
and those in your home directory.

A package is official when every repository that offers it is listed in
`official_repos` and has a SigLevel that requires signatures (see
[Source classes](settings.md#source-classes)). An archive given to `pacman -U`
is a local package; a target whose class cannot be told is treated as
third-party.

## What is reviewed

The hook runs before the transaction (`PreTransaction`, `AbortOnFail`). For
the exact archives being installed it reviews the `.INSTALL` scriptlets and
the payload files that run or grant privileges on their own:

- **Pacman and privileges.** Pacman hooks and the scripts beside them
  (`usr/share/libalpm/hooks` and `scripts`, `etc/pacman.d/hooks`),
  `etc/pacman.conf`, sudoers, `sudo.conf` and `doas.conf`, polkit rules and
  action policies, PAM rules (`etc/pam.d`, `usr/lib/pam.d`, `etc/security`),
  `ld.so.preload`, `ld.so.conf` and `ld.so.conf.d`, and `etc/nsswitch.conf`.
- **systemd.** Units a package enables itself (`*.wants/`, `*.requires/`,
  `*.upholds/`) and unit drop-ins (`<unit>.d/`) under `usr/lib/systemd/system`
  and `user`; manager drop-ins (`*.conf.d/` under `etc/systemd` and
  `usr/lib/systemd`), `etc/systemd/system.conf` and `user.conf`; generators,
  presets and the sleep and shutdown hooks (`system-sleep`,
  `system-shutdown`); and every file in a unit directory systemd reads ahead
  of `usr/lib/systemd`, where a unit stands in for the system's own of that
  name: `etc/systemd/system` and `user` (with `system.control` and
  `system.attached`), `etc/xdg/systemd/user`, `usr/local/lib/systemd/system`
  and `user`, `usr/share/systemd/user` and `usr/local/share/systemd/user`.
- **Boot-time and kernel.** Tmpfiles, sysusers, sysctl, modules-load, binfmt,
  udev, modprobe and environment.d entries, and `etc/environment`; what runs
  at every kernel update: initcpio hooks (`usr/lib/initcpio/hooks`, `install`
  and `post`, `etc/initcpio`), `etc/mkinitcpio.conf`, `mkinitcpio.conf.d` and
  `mkinitcpio.d`, kernel-install scripts (`kernel/install.d` under `usr/lib`
  and `etc`) and a DKMS module's `usr/src/*/dkms.conf`; and the boot entry and
  kernel command line drop-ins (`limine-entry-tool.d`, `etc/cmdline.d`).
- **Login, schedule and network.** Shell start-up and login files
  (`etc/profile`, `etc/profile.d`, `etc/bash.bashrc`, `etc/bash.bash_logout`,
  `etc/zsh`, `etc/fish`, fish's `vendor_conf.d`, xinitrc.d), autostart
  entries, the login screen (`etc/sddm.conf` and the `sddm.conf.d`
  directories, `usr/share/sddm/scripts`, `etc/greetd`, and the sessions in
  `usr/share/wayland-sessions` and `xsessions`), what uwsm sources at a
  graphical login (`usr/share/uwsm/env.d` and `plugins`, `etc/xdg/uwsm`), cron
  jobs (`etc/crontab`, `etc/anacrontab`, `var/spool/cron` and the `cron.*`
  directories), `at` jobs, logrotate configuration (`etc/logrotate.conf`,
  `logrotate.d`), NetworkManager dispatcher scripts, D-Bus services (system
  and session) and system policies, and the SSH configuration
  (`etc/ssh/sshrc`, `sshd_config`, `ssh_config` and their `.d` directories).
- **Tools and `PATH`.** `etc/gitconfig` and git's template hooks,
  `etc/makepkg.conf` and `makepkg.conf.d`, makepkg's shell library
  (`usr/share/makepkg`, sourced by every build, the AUR gate's included), what
  Python runs at every start (`*.pth`, `sitecustomize.py` and
  `usercustomize.py` in `usr/lib/python*/site-packages`, and
  `usr/lib/python*/sitecustomize.py`), and anything in `usr/local/bin` or
  `usr/local/sbin`, which comes before the system's own programs on every
  `PATH`.
- **Desktop, editor and browser.** What other programs read in at every
  start, where a package can add a file without a file conflict: Vim and
  Neovim plugins (`plugin/`, `after/plugin/` and `ftdetect/` under
  `usr/share/vim/vimfiles` and `usr/share/nvim/site`, `plugin/` of a
  `pack/*/start/` package, `usr/share/nvim/runtime/plugin`, `etc/xdg/nvim`,
  `etc/vimrc`, `usr/share/nvim/sysinit.vim`; `autoload/`, `ftplugin/` and
  `syntax/` are read only when a file or a command asks for them, and are not
  reviewed), PipeWire and WirePlumber configuration (`etc/pipewire`,
  `etc/wireplumber`, `*.conf.d` drop-ins), browser policy (Chromium, Chrome,
  Brave, Firefox), Firefox's `distribution` directory and default
  preferences, native-messaging hosts (Chromium, Chrome, Mozilla) and
  system-wide extensions (Chromium, Mozilla), and `etc/tmux.conf` and
  `etc/inputrc`, which tmux and every readline program read at each start.
- **Trust.** Certificate authorities in `etc/ca-certificates/trust-source`
  (its `anchors` included).
- **New users.** In `etc/skel`, the files that would run on their own in a new
  user's home (`.bashrc`, `.config/hypr`, `.config/autostart` and the rest of
  the sweep's user locations), not the whole tree.

For a package that is not from an official repository, shell completions and
functions (`usr/share/bash-completion/completions`, `etc/bash_completion.d`,
`usr/share/zsh/site-functions`, fish's `vendor_completions.d` and
`vendor_functions.d`) and `usr/share/ca-certificates/trust-source` are
reviewed too: an interactive shell, root's included, reads them in. For
official packages they are not, since hundreds ship a completion file and the
Mozilla trust bundle is a megabyte of certificates.

## Files the reviewed files name

A text file of the package that the scriptlet or one of those files names is
reviewed with it: the script a hook hands to an interpreter (`Exec =
/usr/bin/sh /usr/share/pkg/run.sh`), a program a scriptlet calls
(`post_install() { /usr/lib/pkg/setup.sh; }`, or by a bare name the package
ships in `usr/bin`), a file a login script sources, a udev `RUN+=` program, a
cron command. Every word of the file is looked at, not only the first of a
command, and what the named files name is followed in turn, eight files deep
and 500 files per package at most. A path is taken as the system walks it:
`/usr/lib/../share/pkg/run.sh` is `/usr/share/pkg/run.sh`, and a path through
a directory link the package itself ships (`/opt/pkg/current/run.sh` with
`current -> releases/1`) is the file it leads to. A named file that is a
compiled program or other binary data is not read: it is listed as not
reviewed, to you and to the AI. A named text file over 2 MiB, or more files or
steps than those bounds, makes the review incomplete. So does an install
scriptlet or an auto-run file that is over 2 MiB or holds binary data, with
one exception: a compiled program in an auto-run location (a systemd
generator, say) is only listed as not reviewed when the package is from an
official repository. A package with more than 2,000 auto-run files, or more
than 32 MiB of files to review, has none of its auto-run files reviewed, and
the review is incomplete. Those are about
the archive's own bytes, so a permit can overrule them (see [After a
block](permits.md)). A path a script builds at run time (`cd /usr/lib/pkg &&
./setup.sh`), or one behind a variable with nothing of the path before the
file's name (`"$dir/setup.sh"`; `"$pkgdir/usr/lib/pkg/setup.sh"` is found), is
not found.

## Rights a package hands out, and refused paths

A package that ships a symbolic link in place of one of those directories or
of one above it (`etc/cron.d -> /usr/share/x`, or a link for
`usr/share/libalpm`) is refused: what the link leads to would be
read as that directory's files. The same goes for a link in place of a unit's
`.wants` or `.d` directory. A link to another of those directories of the same
kind, named exactly (systemd's `etc/xdg/systemd/user -> ../../systemd/user`),
is fine.

A file installed setuid or setgid root is a local finding (privilege
escalation). Two cases are passed over: a file already installed that way, and
the sandbox helper of a Chromium-based program (told by its name, by that
program's runtime files beside it, and by lying outside the command
directories; like every compiled program, its content is not reviewed). The
finding blocks a package from a third-party repository or a local archive
under every built-in profile; for an official package it is a warning under
`standard` and `local-only`, and blocks under `strict`. The same goes for the
other ways a package hands out rights without a scriptlet: a file with file
capabilities or an access control list (read from the archive itself, since
pacman restores them), a set-id file for another user or group, and a file or
directory under `/usr`, `/etc` or `/opt` that everyone (a sticky directory
aside), a user other than root, or a group other than root's may write. Each
is passed over when the installed file is already that way: for file
capabilities, when it has exactly the ones the package ships (access lists are
not read back, so those are said every time).

Some places are read only by the sweep: every login, program or boot uses
them, and this gate does not review their content. A package that is not from
an official repository and brings a new file into one of them gets the same
finding, which says what a file there does: a PAM module in
`usr/lib/security`, a library in `usr/lib/glibc-hwcaps`, the boot loader's
configuration and the kernel command line (`etc/default/limine`,
`etc/kernel/cmdline`, `boot/limine.conf`), the tables the system is set up by
(`etc/fstab`, `etc/crypttab`, `etc/hosts`), a certificate authority in
`usr/local/share/ca-certificates`, a Podman quadlet in
`etc/containers/systemd` (it becomes a unit at boot), a system-wide Flatpak
override, `etc/npmrc` and `etc/pip.conf`. A file that is already there is
passed over. Official packages ship PAM modules and some of the others
(`filesystem` the tables), so those are let through. What lies under a
reviewed location is reviewed instead and gets no such finding: a certificate
authority in `etc/ca-certificates/trust-source/anchors`, Firefox's
`distribution/policies.json`.

A package that installs a file under `/run`, `/tmp`, `/dev`, `/proc`, `/sys`,
`/root` or `/home`, or lists one under `/bin`, `/sbin`, `/lib`, `/lib64`,
`/usr/sbin` or `/usr/lib64` (links into `/usr` on this system), is refused: no
package's files belong there, and a unit under `/run/systemd` or a key under
`/root/.ssh` would act with nothing looking at it.

## Symbolic links

An auto-run file that is a symbolic link to a file the package does not ship
(a sudoers drop-in linked to `/usr/lib/other/rule`) is reviewed as the file it
leads to. That file is taken from another package of the same transaction if
one ships it; otherwise from this system as it is now, provided only root
could have put it there or can change it. At every link on the way, what the
transaction puts in that place counts.
An unchanged link is reviewed again when the transaction replaces the file it
leads to. A link to a device (`/dev/null`, which masks a unit) or the kernel's
own files is only noted. The review is incomplete when the file is in no archive
of the transaction and not on this system, when someone other than root can
change it or a directory on the way to it, when the transaction puts something
other than a readable file there, when it is over 2 MiB or a directory, or
when it lies behind more than eight links.

The other way round counts too: when a package replaces a file that a symbolic
link already in one of those locations leads to (another package's
`etc/sudoers.d/a -> /usr/share/b/rule`, or a unit you enabled with `systemctl
enable`), the new content is reviewed as that link's file, unless it is
identical to what is installed. A compiled program put there is listed as not
reviewed. The links are read from the system itself,
however deep a directory lies; a location with more than 20,000 entries makes
the review incomplete, and the message names the directory and how many it
holds. In a directory only root can list (`/etc/sudoers.d`,
`/etc/polkit-1/rules.d`) they are read from pacman's record of the packages
that ship into it, so a link root made there by hand is not seen. Which paths
a package has there comes from the file list pacman wrote itself; what each is
comes from the `mtree` the package brought. A listed path the `mtree` does not
describe may be a link to anywhere: the review is incomplete, naming the
package, until a transaction replaces that path or the package is removed.

## What the gate does not see

- A package's other files are installed as shipped and acted on by what is
  already on the system: a pacman hook, DKMS or a systemd generator installed
  earlier reads the new package's files without a review of them.
- A removal is not reviewed.
- A unit a package ships but that you enable yourself later is not reviewed
  then. The sweep lists it, and its later upgrades are reviewed, through the
  link that enables it.

## Upgrades

The install scriptlet is reviewed at every install and upgrade, changed or
not: it runs anew. On an upgrade, an auto-run file identical to the installed
one is not reviewed again, since it adds nothing new: a point release
typically brings a handful of changed files, not every unit and rule. A link
that enables a unit counts as identical only while the unit it leads to is. An
installed file you cannot read (a sudoers drop-in, say) counts as changed and
is reviewed at every upgrade.

These files go to the AI review only; the local pattern rules are written for
scripts and would match the ordinary content of these files. So where the
package's class has `ai = "off"`, they are not reviewed at all: the gate lists
each as not reviewed. A compiled program among them (a generator, for example)
is listed as not reviewed for a package from an official repository, and makes
the review incomplete for any other. A file the reviewed ones name is passed
over the same way when it did not change and every file that names it is
passed over; one the scriptlet names is reviewed every time, since the
scriptlet runs anew. The rest of the payload is not reviewed.

## How archives are located

- For `pacman -S`, each target's sync-database version (`pacman -Si`) is
  looked up in the configured `CacheDir`s (`pacman-conf`) under the file name
  pacman itself gives for it (`pacman -Sp --print-format %f`), and each
  archive's package name is confirmed with `pacman -Qqp`. A cache directory
  that is not root's alone is refused.
- For `pacman -U`, every archive named on pacman's command line is used,
  whatever its file name, resolved against pacman's own working directory.
  Remote URLs are refused, and so are archives named on standard input
  (`pacman -U -`). Dependencies that `pacman -U` pulls from the sync
  repositories in the same transaction are found and classed like `-S`
  targets.
- A transaction given `--root`, `--dbpath`, `--cachedir`, `--sysroot`,
  `--hookdir` or `--gpgdir` (or `-r`, `-b`), or a `--config` other than
  `/etc/pacman.conf` (which yay names on every call), is refused: it runs
  against another system than the one Guardian reads. With `--hookdir` pacman
  leaves out `/etc/pacman.d/hooks`, so the refusal comes from the hook in
  libalpm's own directory, which it always reads.

Each archive must still be the reviewed one when the review is over. Its path
must name the same file, with the size and the times of last write and last
change (the kernel's own, to the nanosecond) it had when it was first read,
and unless the file and every directory above it are root's alone (pacman's
cache), its SHA-256, taken before any of its files is read for the review,
must match again after the AI review has returned: an archive in your own
directory rewritten in place during the AI's minutes blocks the transaction.
Each pass reads the whole archive, so a large one given to `pacman -U` from
your own directory adds the time it takes to read it twice; an archive in
pacman's cache is read once. What no hook can close is the moment between the
hook's exit and pacman opening the file again: keep archives you install with
`pacman -U` where only you and root can write, which the hook also checks.

## Guardian's own package and the reviewer's

Guardian's own program, hooks and scripts may only come from the
`omarchy-guardian` package installed from a local archive (as `install.sh`
does) or an official repository, never from a third-party repository that
offers a package of that name: such a package is refused by its name alone,
whatever it ships, and so is one of that name from anywhere that does not ship
both Guardian's program (`/usr/bin/omarchy-guardian`) and its hook script
(`/usr/lib/omarchy-guardian/guardian-pacman-hook`): an empty "upgrade" would
delete the gate. A package named `claude-code` or `opencode` is refused the
same way unless it comes from an official repository or is named in
`trusted_reviewer_packages` (a top-level key, system file only). A package
that declares it replaces, conflicts with or provides `omarchy-guardian` is
refused, since pacman would remove Guardian for it; one that claims the place
of a reviewer package is refused unless it could ship the reviewer itself. No
package may ship what the reviewer would read as its own instructions or
settings: `etc/opencode`, `etc/claude-code`; `AGENTS.md`, `CLAUDE.md`,
`CLAUDE.local.md`, `CONTEXT.md`, `opencode.json` or `opencode.jsonc` in `/usr`
or `/`; and `.opencode`, `.claude` or `.mcp.json` in `/usr` (a name starting
with `.` at the top of an archive is refused in any case). A local archive
named `omarchy-guardian` is still taken at its word: build Guardian only from
a source you trust.

No package at all, Guardian's own included, may ship `/etc/omarchy-guardian`,
`/var/lib/omarchy-guardian` or `/etc/pacman.d/hooks/omarchy-guardian.hook`
(root's own mark that the gate is on). The reviewers' programs
(`/usr/bin/opencode`, `/usr/local/bin/opencode`, `/usr/bin/claude`,
`/usr/local/bin/claude`, `/opt/claude-code`) may only come from `opencode` or
`claude-code` from an official repository, or from a package named in
`trusted_reviewer_packages`. The tools the gate runs may only come from an
official repository: `bsdtar`, `pacman`, `pacman-conf`, `timeout`, `kill`,
`curl`, `bwrap`, `runuser`, `env`, `sudo`, `sh`, `bash`, `readlink`, `id`,
`getent`, `cut`, `gzip`, `logger` and `journalctl` in `/usr/bin`.

## What the AI review is told

The AI review is told what is under review (the scriptlets and those payload
files) and what routine packaging looks like: capabilities or setuid on the
package's own files, system users, copying its own files into place, its own
services, sockets and device rules, and privileges that only apply once an
administrator opts in (a dedicated, initially empty group, or a boot
credential). The package's text files that a scriptlet or payload file names
are supplied and judged with it. Files that are not supplied (a compiled
program, a file another package provides, one the scriptlet only tells you to
run), and how the package's own programs authorise requests, are out of scope
and not grounds for an inconclusive verdict. It still flags downloading or
running code from elsewhere, sudoers, polkit or PAM rules that grant root
broadly or without authentication, pacman hooks or login and autostart scripts
that run unrelated code, preloaded libraries, persistence the package does not
own, and access to users' home directories or credentials. An inconclusive
verdict blocks in every profile, since ambiguity is something an attacker can
provoke.

## How the hook runs

The hook file is in libalpm's own directory and runs in every transaction.
While `/etc/pacman.d/hooks/omarchy-guardian.hook` does not exist it reads the
targets and exits 0 without reviewing; that link is what `protect` makes.

libalpm runs hooks as children of pacman after `chroot` + `chdir("/")`, so the
hook reads pacman's exact argv from `/proc/<pid>/cmdline` and its working
directory from `/proc/<pid>/cwd`, then drops to the invoking user (`sudo` or
`doas`) for the review. The review starts from an empty environment (`env -i`
with `HOME`, `USER`, `LOGNAME`, `PATH=/usr/bin:/bin` and `LANG`) and uses a
root-owned reviewer from `/usr/bin` or `/usr/local/bin` only. Transactions it
cannot attribute to pacman, to an invoking user, or to an archive are blocked;
pacman run from a root shell, with no invoking user, is one of them. Front
ends that call libalpm directly (for example pamac) are not supported and will
be blocked.