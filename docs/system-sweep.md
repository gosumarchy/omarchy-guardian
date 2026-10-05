# System sweep

`omarchy-guardian sweep` checks what already runs on its own on this machine:
the auto-run locations of the system and of your home, what runs now, and how
the machine was started. This page lists what it reads, how each item is
judged, what the root checks add, how the daily timers work, and how to work
through what it finds. What it cannot see is said where each part is
described.

## Contents

- [What it reads](#what-it-reads)
- [What runs now](#what-runs-now)
- [How the machine was started](#how-the-machine-was-started)
- [How each item is judged](#how-each-item-is-judged)
- [What goes to the review](#what-goes-to-the-review)
- [Root checks](#root-checks)
- [On a schedule](#on-a-schedule)
- [Working through what it finds](#working-through-what-it-finds)

## What it reads

`omarchy-guardian sweep` looks at what already runs on its own, the way
Objective-See's KnockKnock does on macOS: every auto-run location the pacman
gate knows (systemd units and their enable links, drop-ins and generators,
pacman hooks, udev, modprobe, PAM, sudo and polkit rules, shell start-up
files, cron, autostart, D-Bus services, initcpio, the pacman, makepkg, sshd,
logrotate, systemd manager and login-screen configuration, the sessions the
login screen offers, the kernel command line, DKMS build configuration, `at`
jobs, browser policies and native-messaging hosts, certificate authorities,
and Python's `.pth` and `sitecustomize` files, which every Python program runs
at start), a few more only the sweep reads (PAM modules, libraries in
`glibc-hwcaps`, the Limine config, `/etc/fstab` and `/etc/crypttab`, Podman
quadlets in `/etc/containers/systemd`, Firefox's `distribution/policies.json`,
system-wide Flatpak overrides, certificate authorities added in
`/usr/local/share/ca-certificates`, `/etc/hosts`, and the system-wide `npmrc`,
`pip.conf`, `tmux.conf` and `inputrc`) and, in your home, user services (in
`~/.config`, `~/.config/systemd/user.control` and `~/.local/share`) and Podman
quadlets, session D-Bus services, autostart entries, shell files, fish
functions, completions and saved variables, `~/.inputrc`,
`~/.pam_environment`, the X session files, what uwsm sources, the Waybar
configuration, the Hyprland Lua configuration (and what `exec_on_start`
starts), Omarchy hooks, SSH and git configuration, your own Python `.pth`
files, and what the list further down adds.

It follows links and what each file runs, so a trusted service running a
replaced binary, or an interpreter running a script, is checked too: past
wrappers (`sudo -u`, `uwsm app --`, `systemd-run`, `env`, `timeout`, `flock`),
into each command a shell is handed with `-c`, and each command of a line a
shell runs joined with `;`, `&`, `|` or a line break (a crontab's, say), the
first 1024 of each, into the files a shell start-up file reads in with
`source` or `.` and the programs its statements start by a path (on lines up
to 64 KB), the start-up files zsh reads from the directory a `ZDOTDIR=` line
names, a unit's `EnvironmentFile=`, the files and directories a sudoers file
includes, and a Hyprland `.conf`'s `source`, `plugin` and `bind … exec` lines,
with the commands hypridle, hyprlock and their like run (`on-timeout`,
`on-resume`, `lock_cmd`, `before_sleep_cmd` and so on).

A unit's command that runs over several lines (ending in `\`) is read as one,
and `%h`, `%E`, `%S`, `%C` and `%L` (and `%t` in a system unit) are written
out. `~`, `$HOME`, the XDG directories at their default places and a path a
start-up file puts in a variable of its own (`TOOLS=~/opt/tools`, then
`$TOOLS/run`) are understood, other variables are not. A Hyprland `source`
with `*` or `?` in its last part is followed to the files it matches (up to
1024).

The file itself is always reviewed as text; what is not followed is only the
extra look at the program it names. Where one of these limits is reached (or a
chain of more than 8 links), the item says so in its notes and cannot be
allowed, since an allow would vouch for commands nobody followed; and where
the item's text is not reviewed either (a file kept from the AI), the sweep is
**incomplete**.

A file or directory whose name is not valid UTF-8 cannot be checked, and
shells, udev and pacman read such names all the same: the sweep says so and is
**incomplete** (exit 2), as it is when there are more files than it looks
through for setuid programs.

### Programs ahead of the system's own

A program in a directory that comes before `/usr/bin` on `PATH` runs whenever
its name is typed. Which directories those are is read from the real `PATH`s:
the one the sweep runs with, the systemd user manager's (`systemctl --user
show-environment`), and the `PATH` lines of everything a login, a shell or the
session reads: your shell start-up files and the files they `source`,
`/etc/profile` and `/etc/profile.d`, fish's `conf.d`, `environment.d` (yours
and the system's), `~/.pam_environment`, uwsm's `env` files and Hyprland's
`env` lines (Omarchy's own included). A line counts wherever on it the
statement stands (`[ -d ~/.x ] && export PATH=~/.x:$PATH`, inside an `if`,
after `declare -x` or `typeset -x`, among other assignments), in the bash,
zsh, fish and csh forms. A line that sets `PATH` from a command (`PATH=$(…)`)
cannot be followed: the file's item says so in a note, since the directories
it adds are not watched. Where mise is installed or turned on (`mise
activate`), its shims and the directories of what it installed are on the list
too, as they are in an interactive shell. The usual directories
(`~/.local/bin`, `~/.cargo/bin`, `~/bin`, mise's shims, the Go, Bun, Deno,
pnpm, npm and Nix directories) are added where no `PATH` that was read puts
them behind `/usr/bin`; a directory that is ahead of `/usr/bin` in any one of
these is watched. A bare command name in an auto-run file is looked for along
that same list, first where a shell would look first, and every place it is
found in is judged. In each directory on it that someone other than root can
write, the programs named like a command in `/usr/bin` are listed. One named
like a command that asks for a password, fetches or installs (`sudo`, `su`,
`doas`, `pkexec`, `run0`, `ssh`, `scp`, `git`, `gpg`, `pacman`, `yay`, `paru`,
`makepkg`, `systemctl`, `loginctl`, `passwd`, `curl`, `wget`, a shell,
`omarchy`, `omarchy-guardian`) is a high finding wherever it is; `python`,
`node`, `claude`, `opencode` and the `omarchy-*` commands are one too, unless
a version manager put them there: a mise shim (a link to mise itself, as
trusted as that mise) or a program in mise's install directory or
`~/.cargo/bin` is shown as `user-built` at most. A start-up file that puts the
working directory (`.`, or an empty entry) or a temporary or cache directory
on `PATH` is a finding on that file. The file `protect` writes for the
graphical session (`~/.config/uwsm/env.d/90-omarchy-guardian`) is Guardian's
own while it is byte for byte what `protect` wrote, and shown only with
`--all`; with anything else in it, it is a file like any other.

### More that decides what runs

These run nothing by themselves, so each has a plain local rule besides the
review of its text:

- browser flags (`~/.config/chromium-flags.conf`, `chrome-`, `brave-`, `code-`
  and `electron*-flags.conf`): an extension loaded from outside `/usr` and
  `/opt`, a remote-debugging port, a proxy, switched-off web security; browser
  policies in `/etc` that force an extension, a proxy or certificates;
  native-messaging hosts (Chromium, Chrome, Brave, Firefox), whose program is
  followed like any command;
- the shell or command a terminal or prompt starts each time (alacritty, kitty
  with its `startup_session` and `watcher`, ghostty, foot, the `command` and
  `when` of a starship custom module, tmux's `run-shell`, `default-command`
  and `source-file`), followed like any command;
- `mimeapps.list` and the launchers it names in `~/.local/share/applications`:
  one that opens web links (`http`, `https`, `text/html`) without a namesake
  in `/usr/share/applications` is a finding;
- Flatpak overrides that open the sandbox to the home or the host, or let an
  app talk to `org.freedesktop.Flatpak`;
- editor start-up files (`~/.config/nvim/init.lua` and `init.vim`, `plugin/`,
  `after/plugin/` and `lua/`, `~/.vimrc`, `~/.vim/plugin`), and in VS Code's
  `settings.json` the settings that run a folder's tasks unasked, the
  environment and shell of its terminal (`terminal.integrated.env.*` with
  `LD_PRELOAD`, `PATH` and the like, `profiles`, `automationProfile`,
  `shellArgs`), `git.path`, a proxy, switched-off certificate checks and a
  program it is told to run from a temporary or cache directory (the list of
  installed extensions is not read). Of the terminal's environment only the
  variables that change what runs or is loaded count (`PATH`, `LD_PRELOAD`,
  `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV`, `GIT_SSH_COMMAND`, `GIT_CONFIG_*`,
  a proxy and the like, or a compiler from outside the system's directories),
  not `EDITOR`, `PAGER` or an app's own; and a Python interpreter in a virtual
  environment a tool keeps under `~/.cache` (Poetry, uv, pre-commit) or
  `~/.local/share/virtualenvs` is a project's ordinary one;
- mise's configuration (what it sources, its hooks and tasks) and cargo's
  (`rustc-wrapper`, `linker`, `runner`, a credential provider, a replaced
  source or crate, a proxy, variables such as `LD_PRELOAD` under `[env]`),
  whose commands are followed; `~/.npmrc`, pip's, gem's, yarn's, bun's,
  conda's and Go's configuration, `~/.curlrc` and `~/.wgetrc`, where a finding
  is: a registry other than the usual one, a program the tool is told to run
  or code it is told to load (`script-shell`, `git`, `node-options --require`,
  `yarnPath`, `plugins`, `preload`, `-toolexec`, `CC`), a proxy, certificate
  authorities of the file's own or switched-off checks (`strict-ssl`,
  `trusted-host`, `insecure`, `GOINSECURE`, a wide `GOPRIVATE`). What
  developers set every day is not one: a compiler or linker by its name or
  from the system's directories (`linker = "clang"`, the same in `rustflags`,
  `CC = "clang"` under `[env]`), the system's own certificate bundle
  (`/etc/ssl`, `/etc/ca-certificates`, `/usr/share/ca-certificates`), and for
  pip an index of a project's or a company's own over HTTPS
  (`download.pytorch.org`): a pip index is a finding when it is plain
  `http://`, a bare address, a name made to read as another, or a host data is
  dropped off at. One that names a path in a temporary or cache directory, or
  an `http://` address, says so, and each finding names its line. These hold
  registry tokens, so like the SSH and git files they are checked locally and
  never sent to the AI (mise's and cargo's are reviewed, with secret-looking
  values taken out), and what is shown is the key, never the value; so are an
  editor's `settings.json` and fish's saved variables;
- `/etc/hosts`: a line for a host that updates, packages or the AI review come
  from (archlinux.org, omarchy.org, github.com, anthropic.com, the package
  registries) is a finding; a `keyscript=` in `/etc/crypttab` is one too.

### Accounts, keys and trust anchors

Each of these is an item of its own, checked locally and never sent to the AI:
every account with a login shell (a second account with user id 0, and a
system account with a login shell and a password that works, are high
findings), every member of a group that amounts to root (`wheel`, `sudo`,
`root`, `docker`, `lxd`, `incus-admin`, `libvirt`, `disk`, `shadow`), every
key in your `~/.ssh/authorized_keys` and `authorized_keys2` and in the files
`AuthorizedKeysFile` in the server's configuration names, in your home or
anywhere else (`/etc/ssh/keys/%u`, with `%u`, `%U`, `%h` and `%%` written out
for the account; shown by type, SHA-256 fingerprint and comment, as
`ssh-keygen -l` prints them, never the key), and every certificate authority
added in `/etc/ca-certificates/trust-source/anchors` or
`/usr/local/share/ca-certificates`. The files `TrustedUserCAKeys` and
`AuthorizedPrincipalsFile` name are followed like a command. Past 200 keys of
one account the rest are one item ("N more keys", with a hash that moves when
they do), and a key file over 1 MiB, which the SSH server reads all the same,
is an item saying its keys are not listed: both are findings, since neither is
how a key file looks.

Once a sweep has looked at these, one that is new or changed at the next sweep
is a high finding ("a key that may log in as you"), not only a line in
`--diff`; allow the ones you know. The first sweep that sees them has nothing
to compare with and only lists them. For what the root checks report (root's
keys, the accounts, another account's key count), the daily root collector
keeps its own record beside its results, where only root writes, and says
itself which are new, for two days from when it first saw them: what your
sweep remembers is a file of yours, and a program running as you could write a
label into it ahead of time. The collector's very first run has no record to
compare with and says so by sending no list; for that one run your sweep's own
memory stands in.

### Guardian's own units

The daily sweep is a user unit, so a file in your home can replace it or
change any line of it: a drop-in in
`~/.config/systemd/user/omarchy-guardian-sweep.service.d/` that sets `HOME=`,
`XDG_STATE_HOME=` or `ExecStart=`, a unit of the same name earlier on
systemd's search path, a mask, or the same in any other directory of that path
(`systemd-analyze --user unit-paths`): `user.control` and `user.attached`
under `~/.config/systemd`, `~/.local/share/systemd/user`,
`/run/user/<uid>/systemd`, `/etc/systemd/user`, `/etc/xdg/systemd/user`,
`/usr/share/systemd/user` and `/usr/local/share/systemd/user` (both come
before `/usr/lib/systemd/user`), Flatpak's exported data directories, and for
the root checks' units the system's unit directories. Any of these (also a
drop-in for every `omarchy-…` unit or for every service) is a high finding of
its own that cannot be allowed. The root checks report the ones in your home
too, so the finding does not rest on a sweep the override may have redirected;
one that root cannot hash (padded past the read limit, closed to your own
account, not a regular file) is reported by its path alone.

The bar looks for the same files every time it is asked (all but drop-ins
beside the package's own units in `/usr/lib/systemd`, which only the sweep can
tell from one a repository package ships), shows the sweep as partly on, and
lists what the root checks reported.

## What runs now

It also looks at what runs **now**, listing only what does not add up, so a
clean system shows nothing here:

- a running program with no file on disk (deleted, or only in memory), or
  running from a temporary or cache directory. A program an update replaced
  while it runs is fine, but only at a path a repository package owns.
  Anywhere else the file now at that path says nothing about what runs
  (whoever deleted the program may have put it there): the process is reported
  as running a program that is no longer on disk, the file there is not hashed
  in its place, and what it preloads, whether it reads the keyboard and
  whether it listens is checked as for any other. A file that is merely called
  `x (deleted)` is told from a deleted one. In a user namespace of its own a
  deleted program can carry any name, a packaged one included: what that one
  preloads, and whether it reads the keyboard or listens on the network, is
  checked as for a program no package installed;
- a script an interpreter runs from a temporary or cache directory, and a
  program the dynamic loader was handed from one. A script given by a relative
  name is looked for where the process runs now. An AppImage's own start
  script is noted, not flagged. Where an option may or may not take a value,
  both the argument after it and the next are looked at, so a data file in a
  temporary directory passed to a script can be flagged in its place. Code
  given on the command line or on standard input (`python -c`, a `bash -c`
  command string) has no file to look at, and Java classes named by a class
  path are not followed. Where the first argument is not the script (`bash -o
  pipefail x.sh`, `deno run x.ts`), the script is not found;
- a library no repository package installed, loaded into a running program
  (`LD_PRELOAD`, `LD_AUDIT`), and a program told to look for its libraries in
  a temporary directory or in one relative to where it runs
  (`LD_LIBRARY_PATH`; the empty entry launchers leave behind is ignored). This
  is what the process was started with: one that rewrites its own environment
  afterwards is not caught by it;
- a packaged file that is no longer what its package installed. A running
  program, a preloaded library and a loaded kernel module are trusted for
  their content, not for sitting at a packaged path: each is compared with the
  digest pacman recorded (once per file and sweep, up to 2 GiB; past that a
  note says so), and one that differs is a modified package file and is
  checked like a program no package installed. The same comparison runs over
  `/usr/bin`, the libraries at the top of `/usr/lib`, `/usr/lib/security`, the
  programs at the top of `/usr/lib/systemd` and the running kernel's modules
  directory, where a changed file runs sooner or later without being in any
  auto-run location; a file no package owns there is listed as unknown
  (depmod's indexes and DKMS's modules are not). What this finds in `/usr/bin`
  is listed under "The system's own programs". That reads a few gigabytes on
  every sweep, on several threads (a sweep takes about half a minute). One
  change is told apart: a packaged script whose first line alone was rewritten
  to name the same interpreter another way (Omarchy turns `powerprofilesctl`'s
  `#!/usr/bin/env python3` into `#!/bin/python3` on every install). The
  package's content is not on disk, only its digest, so the file is hashed
  again with each line the package could have shipped for that interpreter
  (`#!/usr/bin/env NAME`, `#!/usr/bin/NAME`, `#!/bin/NAME`; for Python also
  `python`, `python3` and `python3.N`) in place of its first; when one gives
  the recorded digest, everything after the first line is the package's, byte
  for byte. The new first line must name a program in `/usr/bin` that a
  repository package installed, with no arguments, and the mode must be
  unchanged. Such a file is listed as `edited` with a note and no alert, and
  is read no more than any other packaged file. Any other difference is
  `modified`;
- a program that listens on the network (TCP, not loopback), by every process
  that shares the socket. The item is named by the program and the port, and
  for an interpreter with no script on disk by what it was told to run too, so
  allowing one does not allow another script or port; a port the kernel picked
  reads `listens`. For `python3 -m module` the item is the file Python runs
  for that module (`/usr/lib/python3.14/http/server.py:tcp-8000`), looked for
  as Python does, first where the process was started and then in the
  interpreter's own library, so the allow is bound to that file's content: a
  module of the same name beside where the command was typed is another item,
  a high finding where it takes the place of the interpreter's own, and one
  more when it runs from a temporary or cache directory. Where the file cannot
  be told for certain, the name carries the module and a mark of the directory
  the process was started in (`/usr/bin/python3:tcp-8000:other:cwd-…`). Only a
  service the process is itself in vouches for it: a packaged unit's own
  control group for the system's services, and for your own services a
  packaged user unit that names the program; an app or terminal scope of your
  session vouches for nothing. A packaged program a packaged service runs, or
  a desktop program known to listen (a browser, Syncthing, KDE Connect,
  Docker), is listed with the trusted items. Any other packaged program that
  listens is shown and flagged low, so a new listener shows in `--diff` and in
  the daily notification; so is an interpreter, the loader, `awk`, `openssl`
  or `busybox`, whatever its script. A program no package installed that waits
  on a UDP port somebody chose is listed the same way (not the common ports:
  DHCP, NTP, SSDP, mDNS, LLMNR). As root, a listening socket that no process
  holds is a high finding, unless a kernel module that serves files (NFS, SMB,
  iSCSI) is loaded;
- a shell or interpreter whose input or output is a network connection, and a
  shell that holds one among its open files (`bash -i >& /dev/tcp/…`, a socket
  duplicated onto standard input in Python, `nc -e`): a remote shell, flagged
  high with the address it is connected to, or medium when that is this
  machine itself. Pipes and local sockets, which terminals, IDEs and language
  servers put there, are not network connections and say nothing. A packaged
  service started per connection is not reported, unless its program is a
  shell;
- a tool that runs or forwards what it is told over the network (`nc`, `ncat`,
  `socat`, `systemd-socket-activate`, `dropbear`, `telnetd`, `chisel`,
  `ngrok`, `cloudflared` and the like) that listens or is connected to another
  machine; an `ssh` that forwards ports (`-R`, `-D`, `-w`) started from no
  terminal; and an `sshd` started with a configuration outside `/etc/ssh`, a
  setting or a port of its own;
- a program no repository package installed that reads the keyboard devices or
  uses a camera, or that holds a raw packet socket (what a sniffer reads the
  network through; the programs that run the network hold some too, and are
  not reported). An interface in promiscuous mode is noted, unless it is part
  of a bridge or a capture tool is running;
- a loaded kernel module no package installed (one built by DKMS is noted, not
  flagged), one the kernel marks out-of-tree or unsigned under an in-tree
  module's name or from a package not known to ship such modules, and the
  kernel's taint flag. A taint only a module sets, with no loaded module that
  carries it, is a hidden module. It is noted instead only where a module that
  would have set that very taint is installed for the running kernel outside
  its own tree, is there as a file and is not loaded now: out-of-tree and
  unsigned for any such module, proprietary only for one with such a licence
  (NVIDIA's, ZFS), never a forced load or a live patch;
- what hides: a process that answers under its number and is missing from the
  list of processes. The numbers the control groups name are tried, and every
  number a process may have, up to the kernel's limit (numbers start over when
  it is reached, so the last one handed out says little); were there ever more
  than can be tried, the newest are and the sweep says so, as it does of a
  share of the numbers its search did not get through. A program named like a
  kernel thread (`[kworker/0:1]`); and, as root, a process root cannot read.
  Root also says when it cannot list the pinned eBPF objects;
- a process attached to another the way a debugger is: high when the other
  holds secrets (a shell, `ssh`, `sudo`, a key agent, a keyring, a browser, a
  password manager), else medium. A program started under its tracer, and a
  packaged debugger at work (`gdb`, `lldb`, `strace`, `perf`, an editor's
  debug adapter), are not reported;
- eBPF objects pinned in `/sys/fs/bpf` that are not systemd's or the traffic
  tools' own (as root only);
- setuid and setgid files, and files with capabilities, under `/usr`, `/opt`,
  `/etc`, `/var`, `/srv`, `/root` and `/home` that no package vouches for; a
  setuid copy of a packaged program counts as unknown. Pacman does not record
  capabilities, so any capability on a packaged file other than exactly those
  its package is known to set is reported: high for all of them (`=ep`) and
  for those that amount to root (`cap_setuid`, `cap_dac_read_search`,
  `cap_sys_admin`, `cap_net_admin`, `cap_bpf` and the like, or one with no
  name), medium for the rest. The search for setuid and setgid files leaves
  out what holds other systems' files: container, machine and Flatpak stores
  under `/var/lib`, `/var/cache`, and snapshot directories (`.snapshots`).
  Other mounted filesystems (`/mnt`, `/media`, `/run/media`) are not looked
  through at all.

As a user only your own processes can be looked at; the root checks see all of
them.

## How the machine was started

It also looks at how the machine was started. The command line of the running
kernel (`/proc/cmdline`) is compared with the boot configuration (Limine's,
`/etc/kernel/cmdline`, and GRUB's and systemd-boot's where they are used): a
parameter that replaces init or the unit to start, opens a shell (`init=`,
`rdinit=`, `systemd.unit=`, `rd.break`), or turns a defence off
(`module.sig_enforce=0`, `lockdown=none`, `selinux=0`, `apparmor=0`,
`audit=0`, `mitigations=off`) and that the configuration does not hold was
typed at the boot menu or put there by something that is not reviewed, and is
a high finding. Every `vmlinuz` under `/boot` (the first 32; more is said) is
compared by SHA-256 with the ones the installed kernel packages ship in
`/usr/lib/modules`. One that matches none is a high finding where it is an
image the machine starts by default or runs now: it goes by an installed
kernel package's name (`vmlinuz-linux`), or its header says it is the running
release. Any other is listed with a note and no alert: Limine with snapper
keeps older kernels for its snapshot entries, and no installed package can
vouch for those. `/boot` is usually root's alone, so this is the root checks'
to do, and your own sweep says so in a note. A note also says whether Secure
Boot is on; that it is off is said once, and after that only with `--all`,
until it changes. The EFI programs (the boot loader itself) and what is inside
the initramfs image are not looked at.

## How each item is judged

Each item is judged against pacman's own records (no network, no hash
lookups). Those records live in `/var/lib/pacman/local`, which root can
rewrite, so the sweep assumes them intact: an attacker who already has root
can make a changed file look packaged. A copy only counts as one when it has
the same name as the packaged file (and never of documentation or examples),
and a link only takes the trust of the unit it enables under that unit's own
name, never for units that open a root shell:

| Tier | Meaning | Shown |
| --- | --- | --- |
| package | Exactly what a repository package installed | with `--all` |
| inert | A masked unit (link to `/dev/null`, or an empty file) or another empty file; not when it masks a defence, Guardian's own sweep included | with `--all` |
| copy | Identical to a file a repository package ships (Omarchy's `etc-overrides`) | with `--all` |
| user-built | From a package of no configured repository (AUR), or from a package file nothing checked (`pacman -U`), whatever its name; or put there by a version manager (mise) | yes |
| edited | A package's configuration file, changed as configuration is meant to be; or a packaged script proven to differ from its package in the spelling of its interpreter line alone (see above) | yes |
| allowed | Allowed with `sweep allow` while unchanged | with `--all` |
| modified | A package's file that is no longer what the package shipped (content, link, set-id or write bits) | yes, and a high finding |
| unknown | No package installed it | yes |

A link of the same name to a packaged file is trusted only where that is how
the thing is enabled (a unit in a systemd unit directory, a hook in pacman's,
a launcher in an autostart directory, a program of `/usr/bin` or `/usr/lib` in
`~/.local/bin` or `~/.cargo/bin`) and the link names its target in full under
`/usr`, `/etc` or `/opt`, never to documentation or an example.

A package counts as a repository's when a repository carries its name and
pacman checked it on the way in: by its signature, or by the checksum the sync
database gave for it (`%VALIDATION%` in the local database says which). A
package file installed by hand with `pacman -U` has neither (`none`), so its
files are `user-built` and reviewed even when it takes the name of a
repository package, and they never vouch for a copy elsewhere; a note names
such packages. The version is not compared with the sync database: a file can
take any version, and a repository package that waits for an update would read
as built by the user.

The defences whose mask is shown are firewalls (`ufw`, `firewalld`,
`nftables`, `iptables`, `ip6tables`, `opensnitchd`), `apparmor`, `auditd` and
`audit-rules`, `usbguard`, `fail2ban`, `sshguard`, `crowdsec`, the ClamAV,
AIDE and rkhunter units, the snapshot timers a rollback needs (`snapper-*`,
`grub-btrfsd`, `limine-snapper-sync`), `systemd-journald` and Guardian's own.
Masking `systemd-resolved` or `systemd-coredump` is common and stays `inert`.

## What goes to the review

Everything shown that holds text goes through the local rules and the AI
review (class `system`), with the review memory, so a repeated sweep of an
unchanged system makes no AI call. Before a file is reviewed, the value of any
assignment whose name has a part that says secret (`KEY`, `APIKEY`, `TOKEN`,
`AUTHTOKEN`, `PAT`, `SECRET`, `PASSWORD`, `PASSWD`, `PASSPHRASE`, `AUTH`,
`CREDENTIAL(S)`, as in `OPENAI_API_KEY`) is taken out when it is a plain
literal, in shell, `NAME=value` (with or without blanks around the `=`), unit
`Environment=` and fish `set` forms: start-up files are where exported keys
live, and the sweep runs on a timer. A value that says where something is (a
path, a URL) stays, since that is what a review needs to see. A secret under
another name, or written some other way, still goes with the file.

SSH and git files in a home directory are checked locally only and never sent
to the AI: an SSH line that runs a command or loads a library (`ProxyCommand`,
`Match … exec`, `PKCS11Provider`, with blanks or `=`), a key with a `command=`
or `environment=` option, and git keys that run a command. A file an SSH
`Include` names is followed and checked the same way (a pattern with `*` is
not). A credential helper is expected and passes, unless it is a shell line of
its own or a program from a temporary directory; `url.*.insteadOf` rewrites
are not judged. Binaries no package vouches for are named to the AI by format
and hash but never run or uploaded.

In what is sent for review, the values of assignments that look like secrets
and the passwords of addresses (`https://user:password@…`) are taken out,
where they are written as plain characters: one with `$`, a backtick or the
like in it could be code a shell runs, and stays to be read.

## Root checks

Some files only root can read (the sudoers file and drop-ins, polkit rules,
root's crontab, shell files and keys, the Limine config). Without root, the
sweep lists them and is **incomplete** (exit 2). `sweep --root` asks for the
sudo password and runs the installed, root-owned Guardian as a collector that
only reads: it never runs what it finds, makes no AI call and writes nothing;
it hands the items no package vouches for back to your own sweep, which judges
them with your settings. Only files of the auto-run locations themselves (a
sudoers drop-in, root's crontab) come back with their content; anything root
reached by following what they run or what a process preloads comes back as a
hash only.

Where a user decides what is named (a crontab or other file that is not root's
alone, or any process, with the arguments and `LD_PRELOAD` it was given), root
looks only at what everyone may read anyway: anything else is not followed, or
is listed as not looked at, with no hash, no kind and no word on whether it
exists, so no user can point the collector at `/etc/shadow` or a key and learn
something about it. That holds through chains of links.

One thing is told of a file not everyone may read: whether a packaged program
a process runs or preloads is still what its package installed. The path must
be one pacman's database holds, reached with no link on the way through
directories that are root's alone, and the answer is that one bit, never the
hash; what the package installed there is public anyway, and a package's
configuration file is never reported this way. Where such a path, in a
directory not everyone may enter, holds no regular file at all, nothing is
said either: "missing" would be a second thing told. So what a user can learn
there by naming a path is that one bit, "a packaged file differs from its
package", and a packaged file that is gone or is something else is left to the
look through the system's own directories, which no user steers. Without it, a
changed program made unreadable (`chmod o-r`) would pass for the packaged one.
A packaged file that lost the read access its package gives everyone is
`modified` in itself, for root and for your own sweep. And what the collector
reads, in its own search for set-id files too, it reaches by entering each
directory as it opened it, so one swapped for a link while it reads is not
followed.

Old password hashes (`/etc/security/opasswd`) are never read. Root's view only
fills in what your own sweep could not read. Crontabs and `at` jobs of other
accounts are left out of the results (a note says how many): only root's, and
those of the accounts in the group allowed to read them (or, for `sweep
--root`, yours) come back. An `at` job starts with the whole environment of
whoever queued it, so it comes back as a hash only.

For the accounts the results go to, the collector also looks into their home:
at what overrides Guardian's user units there (by path and hash, the content
stays), and at the keys that may log in as them. It looks as that account
could look itself: no link is followed, every directory on the way must be one
the account may enter and the file one it may read, as its owner or as anyone,
so a key file that is a link to a file of root's shows nothing and the account
learns nothing it could not have read. Two things go past what the account
could read. An override of Guardian's units that cannot be hashed is reported
by its path, since that it is there is something the account can see itself.
And a key file the SSH server's configuration keeps outside the home
(`AuthorizedKeysFile /etc/ssh/keys/%u`) is read as root where the whole way to
it is root's alone: root wrote the configuration that names it, and what comes
back is what a home's key file gives. Of every other account with a home under
`/home` only the number of keys comes back, with a hash of the list so that a
change shows: whose keys they are is that account's to see, like its crontab
(a key file of theirs too large to read is said in that same line, and no more
of it). Root's own keys come back one by one. Where there are more items than
the results hold, root's own and the system's are kept first and what the
accounts keep under `/home` after them, so an account that fills its home
cannot push root's keys out.

`/etc/shadow` is read for one thing, by its fixed name: whether a system
account that has a login shell also has a password that works, yes or no. No
hash leaves the collector.

## On a schedule

`protect` turns on two timers the package ships:

- a user timer (`omarchy-guardian-sweep.timer`), a few minutes after login and
  then daily, running `sweep --scheduled`: anything new or changed that no
  package vouches for raises a notification ("Guardian found …") that opens
  the saved report, and the bar knight needs attention until you dismiss it.
  Once the timer has run, new is measured against what its own sweeps have
  told about: a sweep run by hand (by you, or by a program that hopes to have
  its files taken as seen) does not count, so you may be notified of something
  you already looked at. A finding that appears on a file that did not change
  counts as a change; one that goes away does not;
- a system timer (`omarchy-guardian-sweep-collect.timer`) for the root checks,
  but only after `protect` asks you and you agree. The answer is kept in the
  system file as `[sweep] root = "allowed"` (or `"declined"`) with the group
  allowed to read the results; a user file cannot set it, and `protect --yes`
  never answers it for you. The collector runs sandboxed (a read-only system,
  no network, no devices beyond the standard ones, and of root's privileges
  only those to read files, look at other users' processes and hand its
  results to your group; only the system calls of an ordinary service, without
  mounting, modules, raw I/O, the clock or tracing; no keys of root's session;
  it is stopped after half an hour) and writes only
  `/var/lib/omarchy-guardian/sweep/root.json` (root-owned, mode 0640, your
  group) and, beside it, its record of the accounts and keys it has seen
  (`trust-seen.json`, root's alone). Your sweep uses the results only while
  they are root's alone and less than 36 hours old. Results written by an
  older Guardian are still read, but count for less: what your own sweep
  leaves to the root checks stays marked as not covered, with a note, until
  the collector has run again. This makes the root-only items it lists (a
  sudoers drop-in no package installed, say) readable by your group, so it is
  only used when your primary group is yours alone; if it is shared with other
  accounts, root checks run only with `sweep --root`. The sandbox limits what
  a bug in the collector could change; it does not contain it: a process that
  is root and may read every file and every other process's memory
  (`CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`) has the secrets of the whole
  machine within reach if it is taken over.

The user unit gives up what the sweep and the AI reviewer it starts do not
need (gaining privileges, making set-id files, real-time priority, another
system-call interface). It cannot be given a read-only system the way the
collector is: in a user unit that puts the sweep into a user namespace of its
own, where every file of root's reads as nobody's, and the sweep could no
longer tell root's files (the list of allowed items, the root checks' results)
from anyone's.

Without root checks (declined, or not answered yet) every sweep is incomplete
and says what it could not check, and the bar shows the sweep as not fully on.
`protect --off` turns both timers off and keeps your answer.

A sweep that only spoke up about what it found would go quiet exactly when it
broke, so every scheduled sweep records when it ran and how it ended (a sweep
you run by hand does not: it says nothing about whether the timer works). A
scheduled sweep that could not run or could not finish (the AI review
unavailable, something it could not check) raises a notification when that
starts or its kind changes, and the bar keeps saying so until a scheduled
sweep finishes. The bar also needs attention when the sweep is on and no
scheduled sweep has run for three days, one started more than two hours ago
and never ended (its unit stops it after an hour), or root checks are on and
their daily results are missing, older than 36 hours or not root's alone (an
hour after boot or login at the earliest, so the timers get their turn first;
after a long suspend it can show for the half hour the timers take to catch
up). The record is a file of yours: it catches a sweep that broke, not a
program running as you that sets out to fake it.

## Working through what it finds

A sweep flags what it cannot vouch for, and some of that will be yours on
purpose: a wrapper in `~/.local/bin`, a keybinding that starts your own tool,
an alias. Look at each one, then either fix it or tell Guardian you know it:

```sh
omarchy-guardian sweep                                 # what is flagged, and why
omarchy-guardian sweep allow '~/.local/bin/claude'     # trust it as it is now (asks for sudo)
omarchy-guardian sweep allow /root/.local/bin/claude   # root's items too
omarchy-guardian sweep --all                           # allowed items show as "allowed"
omarchy-guardian sweep forget '~/.local/bin/claude'    # stop trusting it (or: forget --all)
omarchy-guardian sweep allow --migrate                 # move what an older Guardian allowed
omarchy-guardian sweep --report                        # save the report page and open it
omarchy-guardian status --dismiss                      # clear the bar's alert
```

`sweep --report` saves the same page a notification opens, with the items
listed by area and an **Ask your AI agent** button, and prints the
`omarchy-guardian ask <id>` that opens your agent on it. Use it to go through
the list with your agent without waiting for the daily sweep.

- Use the path exactly as the sweep prints it, with `~/` for your home
  (quoted, so the shell leaves the `~` alone).
- An allow covers the file's current content and what the live checks saw
  about it. If the file changes, or the same program starts reading the
  keyboard, listening on the network or running with extra rights, it is shown
  again and the daily sweep notifies about it.
- Allowing a file stops its alerts, including the AI's, so a sweep with only
  allowed items comes back clear. It does not change the file or make what it
  runs safe: allow what you have read and meant to have.
- Items only root can read (in `/root`, `/etc/sudoers.d`) can be allowed once
  the daily root checks have run (root checks allowed in `protect`); `sweep
  allow` uses their latest results.
- `sweep allow` looks at the item again and allows it as it is at that moment.
  It prints the fingerprint it allows, and where that is not what the last
  sweep showed you (the file changed since, or no sweep has listed it), it
  says so and asks on the terminal first; without a terminal it allows
  nothing. What the last sweep showed is read from the sweep's own record, a
  file of yours: the question catches a file that changed between your reading
  the sweep and allowing it, and nothing more. A program running as you can
  rewrite that record to match, so the fingerprint printed is what to go by.
- Run `sweep allow` and `sweep forget` as yourself, without sudo: they ask for
  the password themselves. Run as root they stop with that advice, since an
  item in a home is allowed for the user who asks.
- What cannot be read at all (a program that exists only in memory, a deleted
  file) cannot be allowed; it stays listed while it runs. Nor can what
  overrides Guardian's own units, or an item whose commands were not all
  followed.
- Every allow is kept in one list only root writes and everyone reads
  (`/var/lib/omarchy-guardian/allowed.json`, mode 0644 in a root-owned 0755
  directory), so `sweep allow` and `sweep forget` ask for the sudo password,
  for items in your home too. Guardian up to 0.7.18 kept it beside root's
  results, in `/var/lib/omarchy-guardian/sweep/`, which only the configured
  group may enter: a second user's allow was written and never read. The root
  half moves the old list on its next run (an allow, a forget or the daily
  root check); until then a sweep that can reach the old one reads it. A
  program running as you can write any file of yours: were the list one of
  them, it could drop an autostart entry and allow it in the same breath. An
  item in a home is kept under the user id it was allowed for, so what you
  allow in your home says nothing about another account's file of the same
  name; `forget --all` drops the system's items and yours, not other
  accounts'.
- Earlier versions of Guardian kept the allows for your home in a file of your
  own (`~/.local/state/omarchy-guardian/sweep/allowed.json`). It no longer
  counts, and a sweep says how many entries it holds. `sweep allow --migrate`
  lists them and, after you say yes and give the sudo password, moves the ones
  whose files are still exactly what you allowed; the rest (changed, gone, or
  not allowable) are named and dropped with the old list. Read the list before
  you say yes: anything running as you could have added to it.
- What the scheduled sweeps have already told you about (`told.json`) is your
  own file too, since the sweep that writes it runs as you: a program already
  running as you can add to it and so quiet a notification for something new
  in your home or the system. The alert itself, and the bar, still show it.
- `--diff` compares with the last sweep. An item that could not be read then
  and can be now (the root checks arrived) is not a change by itself, unless
  it now raises an alert; it is judged like any other in the full sweep.
