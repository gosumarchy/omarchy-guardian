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

For pacman packages: install scriptlets, and files that run without you
starting them (pacman hooks, enabled systemd units, sudoers, polkit, PAM,
udev, tmpfiles, profile scripts, autostart entries; the full list is under
[What is reviewed](#what-is-reviewed)), and the package's own text files those
name. Unchanged files are skipped on upgrade. The same list of locations is
what the [system sweep](system-sweep.md) reads on the installed system.

## What is reviewed

A pre-transaction hook (`AbortOnFail`) that reviews, for the exact archives
being installed, their `.INSTALL` scriptlets and the payload files that run or
grant privileges on their own:

- pacman hooks (`usr/share/libalpm/hooks`, `etc/pacman.d/hooks`), sudoers and
  `doas.conf`, polkit rules and action policies, PAM rules, `ld.so.preload`
  and `ld.so.conf.d`;
- systemd units a package enables itself (`*.wants/`, `*.requires/`,
  `*.upholds/`), generators and presets, and every unit in a directory systemd
  reads ahead of `usr/lib/systemd`, where a unit stands in for the system's
  own of that name: `etc/systemd`, `usr/local/lib/systemd/system` and `user`,
  `usr/share/systemd/user` and `usr/local/share/systemd/user`;
- tmpfiles, sysusers, binfmt, udev, modprobe and environment.d entries;
- login scripts (`etc/profile.d`, xinitrc.d), autostart entries, cron jobs
  (`etc/crontab`, `var/spool/cron` and the `cron.*` directories) and D-Bus
  system services and policies;
- `etc/gitconfig`, `etc/ssh/sshrc`, `etc/makepkg.conf.d`, and anything in
  `usr/local/bin` or `usr/local/sbin`, which comes before the system's own
  programs on every `PATH`;
- what other programs read in at every start, where a package can add a file
  without a file conflict: what uwsm sources at a graphical login
  (`usr/share/uwsm/env.d` and `plugins`, `etc/xdg/uwsm`), Vim and Neovim
  plugins (`plugin/`, `after/plugin/` and `ftdetect/` under
  `usr/share/vim/vimfiles` and `usr/share/nvim/site`, `plugin/` of a
  `pack/*/start/` package, `usr/share/nvim/runtime/plugin`, `etc/xdg/nvim`,
  `etc/vimrc`; `autoload/`, `ftplugin/` and `syntax/` are read only when a
  file or a command asks for them, and are not reviewed), makepkg's shell
  library (`usr/share/makepkg`, sourced by every build, the AUR gate's
  included), git's template hooks, PipeWire and WirePlumber configuration
  (`etc/pipewire`, `*.conf.d` drop-ins), browser policy, preferences and
  native-messaging hosts (Chromium, Chrome, Brave, Firefox), `at` jobs, and
  the boot entry and kernel command line drop-ins (`limine-entry-tool.d`,
  `etc/cmdline.d`);
- certificate authorities in `etc/ca-certificates/trust-source` (its `anchors`
  included), and `etc/tmux.conf` and `etc/inputrc`, which tmux and every
  readline program read at each start;
- in `etc/skel`, the files that would run on their own in a new user's home
  (`.bashrc`, `.config/hypr`, `.config/autostart` and the rest of the sweep's
  user locations), not the whole tree.

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
steps than those bounds, makes the review incomplete; so does an install
scriptlet or an auto-run file over 2 MiB or of binary data. Those are about
the archive's own bytes, so a permit can overrule them (see [After a
block](permits.md)). A path a script builds at run time (`cd /usr/lib/pkg &&
./setup.sh`), or one behind a variable with nothing of the path before the
file's name (`"$dir/setup.sh"`; `"$pkgdir/usr/lib/pkg/setup.sh"` is found), is
not found.

## Rights a package hands out, and refused paths

A package that ships a symbolic link in place of one of those directories
(`etc/cron.d -> /usr/share/x`) is refused: what the link leads to would be
read as that directory's files. The same goes for a link in place of a unit's
`.wants` or `.d` directory. A link to another of those directories of the same
kind, named exactly (systemd's `etc/xdg/systemd/user -> ../../systemd/user`),
is fine.

A file installed setuid or setgid root is a local finding (privilege
escalation) unless it is already installed that way, or is the sandbox helper
of a Chromium-based program (by its name, with that program's runtime files
beside it, outside the command directories; like every compiled program, its
content is not reviewed): it blocks a package from a third-party repository or
a local archive, and is a warning for an official one under the `standard`
profile. The same goes for the other ways a package hands out rights without a
scriptlet: a file with file capabilities or an access control list (read from
the archive itself, since pacman restores them), a set-id file for another
user or group, and a file or directory under `/usr`, `/etc` or `/opt` that
everyone (a sticky directory aside), a user other than root, or a group other
than root's may write. Each is passed over when the installed file is already
that way: for file capabilities, when it has exactly the ones the package
ships (access lists are not read back, so those are said every time).

A package that is not from an official repository and brings a new file into
one of the places only the sweep reads, which every login, program or boot
uses and whose content this gate does not review, gets the same finding, which
says what a file in that place does: a PAM module in `usr/lib/security`, a
library in `usr/lib/glibc-hwcaps`, the boot loader's configuration and the
kernel command line (`etc/default/limine`, `etc/kernel/cmdline`,
`boot/limine.conf`), the tables the system is set up by (`etc/fstab`,
`etc/crypttab`, `etc/hosts`), a certificate authority in
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
leads to: as another package of the same transaction ships it, or as it is on
this system now when root alone could have put it there and may change it; at
every link on the way there, what the transaction puts in that place counts.
An unchanged link is reviewed again when the transaction replaces the file it
leads to. A link to a device (`/dev/null`, which masks a unit) or the kernel's
own files is only noted. A link to a file that neither has, one someone else
can change, or one the transaction puts there as something else, makes the
review incomplete.

The other way round counts too: when a package replaces a file that a symbolic
link already in one of those locations leads to (another package's
`etc/sudoers.d/a -> /usr/share/b/rule`, or a unit you enabled with `systemctl
enable`), the new content is reviewed as that link's file, unless it is
identical to what is installed. The links are read from the system itself,
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

What the gate does not see: a package's other files are installed as shipped
and acted on by what is already on the system (a pacman hook, DKMS or a
systemd generator installed earlier reads the new package's files without a
review of them), a removal is not reviewed, and a unit a package ships but
that you enable yourself later is not reviewed then (the sweep lists it; its
later upgrades are reviewed, through the link that enables it).

## Upgrades

On an upgrade, an auto-run file identical to the installed one is not reviewed
again, since it adds nothing new: a point release typically brings a handful
of changed files, not every unit and rule. A link that enables a unit counts
as identical only while the unit it leads to is. These files go to the AI
review only; the local pattern rules are written for scripts and would match
the ordinary content of these files. Binaries among them (generators, for
example) are listed as not reviewed. A file the reviewed ones name is passed
over the same way when it did not change and every file that names it is
passed over; one the scriptlet names is reviewed every time, since the
scriptlet runs anew. The rest of the payload is not reviewed.

## How archives are located

Archives are located as follows:

- For `pacman -S`, each target's sync-database version (`pacman -Si`) is
  looked up in the configured `CacheDir`s (`pacman-conf`) under the file name
  pacman itself gives for it (`pacman -Sp --print-format %f`), and each
  archive's package name is confirmed with `pacman -Qqp`.
- For `pacman -U`, every archive named on pacman's command line is used,
  whatever its file name, resolved against pacman's own working directory.
  Remote URLs are refused.
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
cache), its SHA-256, taken before anything is read from it, must match again
after the AI review has returned: an archive in your own directory rewritten
in place during the AI's minutes blocks the transaction. Hashing runs at about
175 MiB per second, so a 1 GiB archive adds some twelve seconds for the two
passes. What no hook can close is the moment between the hook's exit and
pacman opening the file again: keep archives you install with `pacman -U`
where only you and root can write, which the hook also checks.

## Guardian's own package and the reviewer's

Guardian's own program, hooks and scripts may only come from the
`omarchy-guardian` package installed from a local archive (as `install.sh`
does) or an official repository, never from a third-party repository that
offers a package of that name: such a package is refused by its name alone,
whatever it ships, and so is one of that name from anywhere that no longer
ships Guardian's program and hook script (an empty "upgrade" would delete the
gate). A package named `claude-code` or `opencode` is refused the same way
unless it comes from an official repository or is named in `[pacman]
trusted_reviewer_packages`. A package that declares it replaces, conflicts
with or provides `omarchy-guardian` is refused, since pacman would remove
Guardian for it; one that claims the place of a reviewer package is refused
unless it could ship the reviewer itself. No package may ship what the
reviewer would read as its own instructions or settings: `etc/opencode`,
`etc/claude-code`, and `AGENTS.md`, `CLAUDE.md`, `CONTEXT.md`,
`opencode.json`, `.opencode` or `.claude` in `/usr` or `/`. A local archive
named `omarchy-guardian` is still taken at its word: build Guardian only from
a source you trust.

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

libalpm runs hooks as children of pacman after `chroot` + `chdir("/")`, so the
hook reads pacman's exact argv from `/proc/<pid>/cmdline` and its working
directory from `/proc/<pid>/cwd`, then drops to the invoking user (`sudo` or
`doas`) for the review. Transactions it cannot attribute to pacman, to an
invoking user, or to an archive are blocked. Front ends that call libalpm
directly (for example pamac) are not supported and will be blocked.
