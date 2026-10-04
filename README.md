# Omarchy Guardian

Omarchy Guardian inspects downloaded source code before you run or install it
on Arch Linux / Omarchy. It is an early, heuristic tool: a clear result is not
a safety guarantee.

## How protection works

Guardian sits in front of the ways Omarchy installs packages, themes and
plugins, and reviews that code **before any of it runs**:

```
 pacman -S / -U / -Syu ──► pacman hook ─────► install scriptlets + auto-run files
 yay (AUR)             ──► makepkg gate ────► PKGBUILD, then the upstream sources
 omarchy theme install ──► theme gate ──────► the theme checkout
 omarchy plugin add    ──► plugin gate ─────► the plugin checkout
                                  │
                   local rules + AI review (Claude Code or OpenCode)
                                  │
             clear ─► the install goes ahead
             risk  ─► blocked, full report in the terminal + desktop notification
```

- **Two reviews.** Fast local rules flag known-bad patterns (download and
  execute, privilege escalation, persistence, credential access and
  exfiltration, encoded commands, destructive operations). An AI reviewer
  then reads the code with every tool switched off and must echo a one-time
  nonce given after the code, so a reply that never read to the end of the
  code cannot pass as a review. The
  code can still try to talk the reviewer into a clean verdict, which is one
  reason the local rules always run too and a clear result is not a
  guarantee.
- **What counts as auto-run.** For pacman packages: install scriptlets, and
  files that run without you starting them (pacman hooks, enabled systemd
  units, sudoers, polkit, PAM, udev, tmpfiles, profile scripts, autostart
  entries). Unchanged files are skipped on upgrade.
- **AUR builds.** The recipe (PKGBUILD) is reviewed before any of it runs.
  makepkg then runs the approved recipe only to download and unpack the
  sources (its top-level code runs; `pkgver()`, `prepare()`, `verify()`,
  `build()` and `package()` do not), and the unpacked sources are reviewed
  before anything is built.
  Plain-HTTP sources without checksums block, and the AUR's own trust signals
  (age, votes, maintainer changes) are part of the review.
- **Fail closed.** A review that cannot finish blocks. An unavailable AI
  blocks community sources; for official Arch/Omarchy updates the `standard`
  profile warns instead, `strict` blocks.
- **Blocks you can read.** A block also raises a desktop notification with
  the Guardian knight. Clicking it opens the full report as a page in your
  browser, saved privately under `~/.cache/omarchy-guardian/reports` (the
  newest 20 are kept; nothing is saved when Guardian runs as root). The page
  runs no scripts and loads nothing. Everything quoted from the reviewed code
  is escaped, and control and invisible characters are shown as codes, in the
  page and in the terminal alike. Its *Ask your AI agent* button opens Claude
  Code (or OpenCode) in a terminal with the report. The agent runs with every
  tool, MCP server and your own agent settings switched off, so it can only
  talk. It is told to treat the report as untrusted, but treat its answer as
  advice: never run a command because the report or the agent quotes it. The
  report is passed on the agent's command line, which other local users can
  read.
- **In your bar.** The Guardian knight sits in the bar: calm when every gate
  is on, red-eyed when something needs attention (a gate is off, a setting is
  broken, the daily sweep stopped running or could not finish, or a block in
  the last day is unseen), dim when protection is off. A gate that cannot
  be there (the package's files are missing) counts as a problem; the AUR
  gate without yay installed does not. A gate counts as on only when it is
  in effect, not when a line that looks like it is in a file: the Bash
  interceptor's exact line where Bash runs it and with nothing after it that
  unsets or replaces its functions, the menu entries that are in effect when
  the menu reads its file, yay building through Guardian's root-owned shim
  with no alias, function or other `yay` in front of it, and Guardian's
  theme and plugin commands first on the session's PATH. Anything less
  reads "partly on" with the reason. paru, pikaur, aura or trizen installed
  without the gate is a problem too. A class set weaker than its protection
  level (the AI review lowered or off, findings that only warn, the no-AI
  level's question taken away) is a problem until you set it back or accept
  it with `omarchy-guardian config acknowledge`; accepted, it says "local
  checks only" or "findings only warn" beside the gate. When a gate that
  was on goes off or partly off without you turning it off through
  Guardian, or a class becomes weaker, you get one notification
  ("Guardian protection changed"), from the bar's own check or the daily
  sweep; a gate that dropped stays listed until it is back on or
  `omarchy-guardian status --dismiss`. That record is a file of your own,
  like the list of dismissed blocks: it catches things breaking and crude
  tampering (a line removed from `~/.bashrc`), not a program running as you
  that also rewrites the record. A dismissed-blocks mark that names a
  report newer than any saved one is not believed.
  In Waybar its tooltip lists the gates, problems and last block; left-click
  opens the settings app and right-click the last report. In Omarchy's shell
  bar it opens a panel with the same details and tiles for the report,
  turning protection on or off, and the settings. `omarchy-guardian protect`
  adds it to whichever bar you run.
- **Nothing to babysit.** The settings app (`omarchy-guardian tui`) turns
  every gate on with *Protect everything*, picks the protection level and the
  model, and tests the reviewer with a malicious and a harmless sample.
- **Not covered.** Programs you download and run yourself, `curl | sh`
  pasted into a terminal, Flatpak, npm, pip, mise and other language package
  managers, and the binaries inside a package (only what runs at install or
  boot is reviewed). `omarchy-guardian guard` and `sandbox` cover a download
  you start by hand.

It is a single Rust binary with **no third-party crates**. SHA-256, JSON, and
the small subset of TOML it needs are implemented in the crate so the whole
gate can be audited in one place. It builds only for Linux.

## Commands

```sh
omarchy-guardian scan ./downloaded-project
omarchy-guardian scan --thorough --hashes ./theme-checkout
omarchy-guardian guard --thorough ./aur-build-directory -- makepkg --noconfirm
omarchy-guardian sandbox ./theme-checkout -- /usr/bin/true
omarchy-guardian sweep
```

- `scan` reviews a file or directory and prints a report.
- `guard` reviews, then re-hashes the tree, then **replaces itself** with the
  command (`exec`) only if the review was clear or warned and nothing
  changed. A warned review is one with something left unread that the
  class's settings allow: an unavailable AI review under `ai = optional`,
  or a skipped tool directory (see below).
  `--exclude NAME` (repeatable) leaves a top-level directory (never a file
  or link of that name) out of both the
  review and the snapshot.
- `tui` (or `settings`) opens the settings app: a full-screen terminal UI in
  Omarchy's style, simple by default, with every setting under `--expert`
  (see [Settings app](#settings-app)).
- `sandbox` reviews, copies the tree (without `.git`) to a private temporary
  directory, proves the copy matches the reviewed snapshot, and runs the
  command in Bubblewrap
  with the network isolated, no host home directory and a read-only system.
  It is a behaviour smoke test, not a dynamic malware detector.
- `sweep` checks what already runs on its own on this machine (see
  [System sweep](#system-sweep)). `--root` also checks what only root can
  read now, `--all` lists trusted items too, `--diff` only what changed since
  the last sweep, `--json` prints one JSON document. `sweep allow PATH`
  trusts one item as it is now; `sweep forget PATH` (or `--all`) undoes it.
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

## System sweep

`omarchy-guardian sweep` looks at what already runs on its own, the way
Objective-See's KnockKnock does on macOS: every auto-run location the pacman
gate knows (systemd units and their enable links, drop-ins and generators,
pacman hooks, udev, modprobe, PAM, sudo and polkit rules, shell start-up
files, cron, autostart, D-Bus services, initcpio, the pacman, makepkg, sshd,
logrotate, systemd manager and login-screen configuration, the sessions the
login screen offers, the kernel command line, DKMS build configuration, and
Python's `.pth` and `sitecustomize` files, which every Python program runs
at start), a few more only the sweep reads (PAM modules, libraries in
`glibc-hwcaps`, the Limine config, `/etc/fstab` and `/etc/crypttab`, Podman
quadlets in `/etc/containers/systemd`, `at` jobs, browser policies and
native-messaging hosts, system-wide Flatpak overrides, added certificate
authorities and `/etc/hosts`) and, in your home, user services (in
`~/.config`, `~/.config/systemd/user.control` and `~/.local/share`) and
Podman quadlets, session D-Bus services, autostart
entries, shell files, fish functions, completions and saved variables,
`~/.inputrc`, `~/.pam_environment`, the X session files, what uwsm sources,
the Waybar
configuration, the Hyprland Lua configuration (and what `exec_on_start`
starts), Omarchy hooks, SSH and git configuration, your own Python `.pth`
files, and what the list further down adds. It
follows links and what each file runs, so a trusted service running a
replaced binary, or an interpreter running a script, is checked too: past
wrappers (`sudo -u`, `uwsm app --`, `systemd-run`, `env`, `timeout`,
`flock`), into each command a shell is handed with `-c`, and each command of a
line a shell runs joined with `;`, `&`, `|` or a line break (a crontab's,
say), the first 1024 of each,
into the files a shell start-up file reads in with `source` or `.` and
the programs its statements start by a path (on lines up to 64 KB), the
start-up files zsh reads from the directory a `ZDOTDIR=` line names, a
unit's `EnvironmentFile=`, the files and directories a sudoers file
includes, and a Hyprland `.conf`'s
`source`, `plugin` and `bind … exec` lines, with the commands hypridle,
hyprlock and their like run (`on-timeout`, `on-resume`, `lock_cmd`,
`before_sleep_cmd` and so on). A unit's command that runs over several
lines (ending in `\`) is read as one, and `%h`, `%E`, `%S`, `%C` and `%L`
(and `%t` in a system unit) are written out. `~`, `$HOME`,
the XDG directories at their default places and a path a start-up file
puts in a variable of its own (`TOOLS=~/opt/tools`, then `$TOOLS/run`)
are understood, other variables are not. A Hyprland `source` with `*` or
`?` in its last part is followed to the files it matches (up to 1024). The
file itself is always reviewed as text; what is not followed is only the
extra look at the program it names. Where one of these limits is reached
(or a chain of more than 8 links), the item says so in its notes and
cannot be allowed, since an allow would vouch for commands nobody
followed; and where the item's text is not reviewed either (a file kept
from the AI), the sweep is **incomplete**.

**Programs ahead of the system's own.** A program in a directory that
comes before `/usr/bin` on `PATH` runs whenever its name is typed. Which
directories those are is read from the real `PATH`s: the one the sweep
runs with, the systemd user manager's (`systemctl --user
show-environment`), and the `PATH` lines of your shell start-up files
(bash, zsh and fish forms, where they are written out), with the usual ones
(`~/.local/bin`, `~/.cargo/bin`, `~/bin`, mise's shims, the Go, Bun, Deno,
pnpm, npm and Nix directories) added where no `PATH` that was read puts
them behind `/usr/bin`. A bare command name in an auto-run file is looked
for along that same list, first where a shell would look first, and every
place it is found in is judged. In each directory on it that someone other
than root can write, the programs named like a command in `/usr/bin` are
listed. One named like a command that asks for a password, fetches or
installs (`sudo`, `su`, `doas`, `pkexec`, `run0`, `ssh`, `scp`, `git`,
`gpg`, `pacman`, `yay`, `paru`, `makepkg`, `systemctl`, `loginctl`,
`passwd`, `curl`, `wget`, a shell, `omarchy-guardian`) is a high finding
wherever it is; `python`, `node`, `claude`, `opencode` and the `omarchy-*`
commands are one too, unless a version manager put them there: a mise shim
(a link to mise itself, as trusted as that mise) or a program in mise's
install directory or `~/.cargo/bin` is shown as `user-built` at most. A
start-up file that puts the working directory (`.`, or an empty entry) or
a temporary or cache directory on `PATH` is a finding on that file.

**More that decides what runs.** These run nothing by themselves, so each
has a plain local rule besides the review of its text:

- browser flags (`~/.config/chromium-flags.conf`, `chrome-`, `brave-`,
  `code-` and `electron*-flags.conf`): an extension loaded from outside
  `/usr` and `/opt`, a remote-debugging port, a proxy, switched-off web
  security; browser policies in `/etc` that force an extension, a proxy or
  certificates; native-messaging hosts (Chromium, Chrome, Brave, Firefox),
  whose program is followed like any command;
- the shell or command a terminal or prompt starts each time (alacritty,
  kitty with its `startup_session` and `watcher`, ghostty, foot, the
  `command` and `when` of a starship custom module, tmux's `run-shell`,
  `default-command` and `source-file`), followed like any command;
- `mimeapps.list` and the launchers it names in
  `~/.local/share/applications`: one that opens web links (`http`, `https`,
  `text/html`) without a namesake in `/usr/share/applications` is a
  finding;
- Flatpak overrides that open the sandbox to the home or the host, or let
  an app talk to `org.freedesktop.Flatpak`;
- editor start-up files (`~/.config/nvim/init.lua` and `init.vim`,
  `plugin/`, `after/plugin/` and `lua/`, `~/.vimrc`, `~/.vim/plugin`), and
  the two VS Code settings that run a folder's tasks unasked (the list of
  installed extensions is not read);
- mise's configuration (what it sources, its hooks and tasks) and cargo's
  (`rustc-wrapper`, `linker`, `runner`, a replaced source), whose commands
  are followed; `~/.npmrc`, pip's, gem's, yarn's, bun's and Go's
  configuration, where a registry other than the usual one, a
  `script-shell`, a `trusted-host`, `-toolexec` or switched-off checks are
  findings. These hold registry tokens, so like the SSH and git files they
  are checked locally and never sent to the AI (mise's and cargo's are
  reviewed, with secret-looking values taken out); so are an editor's
  `settings.json` and fish's saved variables;
- `/etc/hosts`: a line for a host that updates, packages or the AI review
  come from (archlinux.org, omarchy.org, github.com, anthropic.com, the
  package registries) is a finding; a `keyscript=` in `/etc/crypttab` is
  one too.

**Accounts, keys and trust anchors.** Each of these is an item of its own,
checked locally and never sent to the AI: every account with a login shell
(a second account with user id 0, and a system account with a login shell
and a password that works, are high findings), every member of a group
that amounts to root (`wheel`, `sudo`, `root`, `docker`, `lxd`,
`incus-admin`, `libvirt`, `disk`, `shadow`), every key in your
`~/.ssh/authorized_keys` and `authorized_keys2` and in the files
`AuthorizedKeysFile` in the server's configuration names (shown by type,
SHA-256 fingerprint and comment, as `ssh-keygen -l` prints them, never the
key), and every certificate authority added in
`/etc/ca-certificates/trust-source/anchors` or
`/usr/local/share/ca-certificates`. The files `TrustedUserCAKeys` and
`AuthorizedPrincipalsFile` name are followed like a command. Once a sweep
has looked at these, one that is new or changed at the next sweep is a
high finding ("a key that may log in as you"), not only a line in
`--diff`; allow the ones you know. The first sweep that sees them has
nothing to compare with and only lists them.

**Guardian's own units.** The daily sweep is a user unit, so a file in
your home can replace it or change any line of it: a drop-in in
`~/.config/systemd/user/omarchy-guardian-sweep.service.d/` that sets
`HOME=`, `XDG_STATE_HOME=` or `ExecStart=`, a unit of the same name earlier
on systemd's search path, a mask, or the same in
`~/.config/systemd/user.control/`, `~/.local/share/systemd/user`,
`/run/user/<uid>/systemd`, `/etc/systemd/user` and for the root checks'
units in the system's unit directories. Any of these (also a drop-in for
every `omarchy-…` unit or for every service) is a high finding of its own
that cannot be allowed. The root checks report the ones in your home too,
so the finding does not rest on a sweep the override may have redirected.

A link of the same name to a
packaged file is trusted only
where that is how the thing is enabled (a unit in a systemd unit
directory, a hook in pacman's, a launcher in an autostart directory, a
program of `/usr/bin` or `/usr/lib` in `~/.local/bin` or `~/.cargo/bin`)
and the link names its target in full under `/usr`, `/etc` or `/opt`,
never to
documentation or an example.

It also looks at what runs **now**, listing only what does not add up, so a
clean system shows nothing here:

- a running program with no file on disk (deleted, or only in memory), or
  running from a temporary or cache directory. A program an update
  replaced while it runs is fine, but only at a path a repository package
  owns. Anywhere else the file now at that path says nothing about what
  runs (whoever deleted the program may have put it there): the process is
  reported as running a program that is no longer on disk, the file there
  is not hashed in its place, and what it preloads, whether it reads the
  keyboard and whether it listens is checked as for any other. A file that
  is merely called `x (deleted)` is told from a deleted one. In a user
  namespace of its own a deleted program can carry any name, a packaged
  one included: what that one preloads, and whether it reads the keyboard
  or listens on the network, is checked as for a program no package
  installed;
- a script an interpreter runs from a temporary or cache directory, and a
  program the dynamic loader was handed from one. A script given by a
  relative name is looked for where the process runs now. An AppImage's own
  start script is noted, not flagged. Where an option may or may not take a
  value, both the argument after it and the next are looked at, so a data
  file in a temporary directory passed to a script can be flagged in its
  place. Code given on the command line or on standard input (`python -c`,
  a `bash -c` command string) has no file to look at, and Java classes
  named by a class path are not followed. Where the first argument is not
  the script (`bash -o pipefail x.sh`, `deno run x.ts`), the script is not
  found;
- a library no repository package installed, loaded into a running
  program (`LD_PRELOAD`, `LD_AUDIT`), and a program told to look for its
  libraries in a temporary directory or in one relative to where it runs
  (`LD_LIBRARY_PATH`; the empty entry launchers leave behind is ignored).
  This is what the process was started with: one that rewrites its own
  environment afterwards is not caught by it;
- a packaged file that is no longer what its package installed. A running
  program, a preloaded library and a loaded kernel module are trusted for
  their content, not for sitting at a packaged path: each is compared with
  the digest pacman recorded (once per file and sweep, up to 2 GiB; past
  that a note says so), and one that differs is a modified package file
  and is checked like a program no package installed. The same comparison
  runs over `/usr/bin`, the libraries at the top of `/usr/lib`,
  `/usr/lib/security`, the programs at the top of `/usr/lib/systemd` and
  the running kernel's modules directory, where a changed file runs sooner
  or later without being in any auto-run location; a file no package owns
  there is listed as unknown (depmod's indexes and DKMS's modules are
  not). That reads a few gigabytes on every sweep, on several threads;
- a program that listens on the network (TCP, not loopback), by every
  process that shares the socket. The item is named by the program and the
  port, and for an interpreter with no script on disk by what it was told
  to run too (`/usr/bin/python3:tcp-8000:http.server`), so allowing one
  does not allow another script or port; a port the kernel picked reads
  `listens`. A packaged program a packaged service runs, or a desktop
  program known to listen (a browser, Syncthing, KDE Connect, Docker), is
  listed with the trusted items. Any other packaged program that listens
  is shown and flagged low, so a new listener shows in `--diff` and in the
  daily notification; so is an interpreter, the loader, `awk`, `openssl`
  or `busybox`, whatever its script. A program no package installed that
  waits on a UDP port somebody chose is listed the same way (not the
  common ports: DHCP, NTP, SSDP, mDNS, LLMNR). As root, a listening socket
  that no process holds is a high finding, unless a kernel module that
  serves files (NFS, SMB, iSCSI) is loaded;
- a shell or interpreter whose input or output is a network connection,
  and a shell that holds one among its open files (`bash -i >&
  /dev/tcp/…`, a socket duplicated onto standard input in Python, `nc
  -e`): a remote shell, flagged high with the address it is connected to,
  or medium when that is this machine itself. Pipes and local sockets,
  which terminals, IDEs and language servers put there, are not network
  connections and say nothing. A packaged service started per connection
  is not reported, unless its program is a shell;
- a tool that runs or forwards what it is told over the network (`nc`,
  `ncat`, `socat`, `systemd-socket-activate`, `dropbear`, `telnetd`,
  `chisel`, `ngrok`, `cloudflared` and the like) that listens or is
  connected to another machine; an `ssh` that forwards ports (`-R`, `-D`,
  `-w`) started from no terminal; and an `sshd` started with a
  configuration outside `/etc/ssh`, a setting or a port of its own;
- a program no repository package installed that reads the keyboard
  devices or uses a camera, or that holds a raw packet socket (what a
  sniffer reads the network through; the programs that run the network
  hold some too, and are not reported). An interface in promiscuous mode
  is noted, unless it is part of a bridge or a capture tool is running;
- a loaded kernel module no package installed (one built by DKMS is noted,
  not flagged), one the kernel marks out-of-tree or unsigned under an
  in-tree module's name or from a package not known to ship such modules,
  and the kernel's taint flag. A taint only a module sets, with no loaded
  module that carries it, is a hidden module (noted instead where an
  installed out-of-tree module is not loaded now and may have set it);
- what hides: a process that answers under its number and is missing from
  the list of processes (the numbers the control groups name are tried,
  and every number while the system has handed out fewer than 250,000); a
  program named like a kernel thread (`[kworker/0:1]`); and, as root, a
  process root cannot read;
- a process attached to another the way a debugger is: high when the
  other holds secrets (a shell, `ssh`, `sudo`, a key agent, a keyring, a
  browser, a password manager), else medium. A program started under its
  tracer, and a packaged debugger at work (`gdb`, `lldb`, `strace`,
  `perf`, an editor's debug adapter), are not reported;
- eBPF objects pinned in `/sys/fs/bpf` that are not systemd's or the
  traffic tools' own (as root only);
- setuid and setgid files, and files with capabilities, under `/usr`,
  `/opt`, `/etc`, `/var`, `/srv`, `/root` and `/home` that no package
  vouches for; a setuid copy of a packaged program counts as unknown.
  Pacman does not record capabilities, so any capability on a packaged
  file other than exactly those its package is known to set is reported:
  high for all of them (`=ep`) and for those that amount to root
  (`cap_setuid`, `cap_dac_read_search`, `cap_sys_admin`, `cap_net_admin`,
  `cap_bpf` and the like, or one with no name), medium for the rest. The
  search for setuid and setgid files leaves out what holds other systems'
  files: container, machine and Flatpak stores under `/var/lib`,
  `/var/cache`, and snapshot directories (`.snapshots`). Other mounted
  filesystems (`/mnt`, `/media`, `/run/media`) are not looked through at
  all.

As a user only your own processes can be looked at; the root checks see
all of them.

It also looks at how the machine was started. The command line of the
running kernel (`/proc/cmdline`) is compared with the boot configuration
(Limine's, `/etc/kernel/cmdline`, and GRUB's and systemd-boot's where they
are used): a parameter that replaces init or the unit to start, opens a
shell (`init=`, `rdinit=`, `systemd.unit=`, `rd.break`), or turns a defence
off (`module.sig_enforce=0`, `lockdown=none`, `selinux=0`, `apparmor=0`,
`audit=0`, `mitigations=off`) and that the configuration does not hold was
typed at the boot menu or put there by something that is not reviewed, and
is a high finding. Every `vmlinuz` under `/boot` is compared by SHA-256
with the ones the installed kernel packages ship in `/usr/lib/modules`; one
that matches none is a high finding. `/boot` is usually root's alone, so
this is the root checks' to do, and your own sweep says so in a note. A
note also says whether Secure Boot is on. The EFI programs (the boot loader
itself) and what is inside the initramfs image are not looked at.

A file or directory whose name is not valid UTF-8 cannot be checked, and
shells, udev and pacman read such names all the same: the sweep says so and
is **incomplete** (exit 2), as it is when there are more files than it
looks through for setuid programs.

Each item is judged against pacman's own records (no network, no hash
lookups). Those records live in `/var/lib/pacman/local`, which root can
rewrite, so the sweep assumes them intact: an attacker who already has root
can make a changed file look packaged. A copy only counts as one when it
has the same name as the packaged file (and never of documentation or
examples), and a link only takes the trust of the unit it enables under that
unit's own name, never for units that open a root shell:

| Tier | Meaning | Shown |
|---|---|---|
| package | Exactly what a repository package installed | with `--all` |
| inert | A masked unit (link to `/dev/null`, or an empty file) or another empty file; not when it masks a defence, Guardian's own sweep included | with `--all` |
| copy | Identical to a file a repository package ships (Omarchy's `etc-overrides`) | with `--all` |
| user-built | From a package of no configured repository (AUR), or from a package file nothing checked (`pacman -U`), whatever its name; or put there by a version manager (mise) | yes |
| edited | A package's configuration file, changed as configuration is meant to be | yes |
| allowed | Allowed with `sweep allow` while unchanged | with `--all` |
| modified | A package's file that is no longer what the package shipped (content, link, set-id or write bits) | yes, and a high finding |
| unknown | No package installed it | yes |

A package counts as a repository's when a repository carries its name
and pacman checked it on the way in: by its signature, or by the checksum
the sync database gave for it (`%VALIDATION%` in the local database says
which). A package file installed by hand with `pacman -U` has neither
(`none`), so its files are `user-built` and reviewed even when it takes the
name of a repository package, and they never vouch for a copy elsewhere; a
note names such packages. The version is not compared with the sync
database: a file can take any version, and a repository package that waits
for an update would read as built by the user.

The defences whose mask is shown are firewalls (`ufw`, `firewalld`,
`nftables`, `iptables`, `ip6tables`, `opensnitchd`), `apparmor`, `auditd`
and `audit-rules`, `usbguard`, `fail2ban`, `sshguard`, `crowdsec`, the
ClamAV, AIDE and rkhunter units, the snapshot timers a rollback needs
(`snapper-*`, `grub-btrfsd`, `limine-snapper-sync`), `systemd-journald` and
Guardian's own. Masking `systemd-resolved` or `systemd-coredump` is common
and stays `inert`.

Everything shown that holds text goes through the local rules and the AI
review (class `system`), with the review memory, so a repeated sweep of an
unchanged system makes no AI call. Before a file is reviewed, the value of
any assignment whose name has a part that says secret (`KEY`, `APIKEY`,
`TOKEN`, `AUTHTOKEN`, `PAT`, `SECRET`, `PASSWORD`, `PASSWD`, `PASSPHRASE`,
`AUTH`, `CREDENTIAL(S)`, as in `OPENAI_API_KEY`) is taken out when it is a plain literal, in shell,
`NAME=value` (with or without blanks around the `=`), unit `Environment=`
and fish `set` forms: start-up files are
where exported keys live, and the sweep runs on a timer. A value that says
where something is (a path, a URL) stays, since that is what a review needs
to see. A secret under another name, or written some other way, still goes
with the file.
SSH and git files in a home directory are checked locally only and never
sent to the AI: an SSH line that runs a command or loads a library
(`ProxyCommand`, `Match … exec`, `PKCS11Provider`, with blanks or `=`), a
key with a `command=` or `environment=` option, and git keys that run a
command. A file an SSH `Include` names is followed and checked the same
way (a pattern with `*` is not). A credential helper
is expected and passes, unless it is a shell line of its own or a program
from a temporary directory; `url.*.insteadOf` rewrites are not judged.
Binaries no package vouches for are named to the AI by format and hash but
never run or uploaded.

Some files only root can read (the sudoers file and drop-ins, polkit rules,
root's crontab, shell files and keys, the Limine config). Without root, the
sweep lists them and is **incomplete** (exit 2). `sweep --root` asks for the
sudo password and runs the installed, root-owned Guardian as a collector
that only reads: it never runs what it finds, makes no AI call and writes
nothing; it hands the items no package vouches for back to your own sweep,
which judges them with your settings. Only files of the auto-run locations
themselves (a sudoers drop-in, root's crontab) come back with their
content; anything root reached by following what they run or what a process
preloads comes back as a hash only. Where a user decides what is named (a
crontab or other file that is not root's alone, or any process, with the
arguments and `LD_PRELOAD` it was given), root looks only at what everyone
may read anyway: anything else is not followed, or is listed as not looked
at, with no hash, no kind and no word on whether it exists, so no user can
point the collector at `/etc/shadow` or a key and learn something about it.
That holds through chains of links. And what the collector reads, in its
own search for set-id files too, it reaches by entering each directory as
it opened it, so one swapped for a link while it reads is not followed.
Old password hashes
(`/etc/security/opasswd`) are never read. Root's view only fills in what
your own sweep could not read. Crontabs and `at` jobs of other accounts are
left out of the results (a note says how many): only root's, and those of
the accounts in the group allowed to read them (or, for `sweep --root`,
yours) come back. An `at` job starts with the whole environment of whoever
queued it, so it comes back as a hash only.

For the accounts the results go to, the collector also looks into their
home: at what overrides Guardian's user units there (by path and hash, the
content stays), and at the keys that may log in as them. It looks as that
account could look itself: no link is followed, every directory on the way
must be one the account may enter and the file one it may read, as its
owner or as anyone, so a key file that is a link to a file of root's shows
nothing and the account learns nothing it could not have read. Of every
other account with a home under `/home` only the number of keys comes back,
with a hash of the list so that a change shows: whose keys they are is that
account's to see, like its crontab. Root's own keys come back one by one.
`/etc/shadow` is read for one thing, by its fixed name: whether a system
account that has a login shell also has a password that works, yes or no.
No hash leaves the collector.

In what is sent for review, the values of assignments that look
like secrets and the passwords of addresses (`https://user:password@…`)
are taken out, where they are written as plain characters: one with `$`,
a backtick or the like in it could be code a shell runs, and stays to be
read.

**On a schedule.** `protect` turns on two timers the package ships:

- a user timer (`omarchy-guardian-sweep.timer`), a few minutes after login
  and then daily, running `sweep --scheduled`: anything new or changed that
  no package vouches for raises a notification ("Guardian found …") that
  opens the saved report, and the bar knight needs attention until you
  dismiss it. Once the timer has run, new is measured against what its own
  sweeps have told about: a sweep run by hand (by you, or by a program that hopes to have
  its files taken as seen) does not count, so you may be notified of
  something you already looked at. A finding that appears on a file that
  did not change counts as a change; one that goes away does not;
- a system timer (`omarchy-guardian-sweep-collect.timer`) for the root
  checks, but only after `protect` asks you and you agree. The answer is
  kept in the system file as `[sweep] root = "allowed"` (or `"declined"`)
  with the group allowed to read the results; a user file cannot set it,
  and `protect --yes` never answers it for you. The collector runs
  sandboxed (a read-only system, no network, no devices beyond the standard
  ones, and of root's privileges only
  those to read files, look at other users' processes and hand its results
  to your group; only the system calls of an ordinary service, without
  mounting, modules, raw I/O, the clock or tracing; no keys of root's
  session; it is stopped after half an hour) and writes only
  `/var/lib/omarchy-guardian/sweep/root.json` (root-owned, mode 0640, your
  group). Your sweep uses it only while it is root's alone and less than 36
  hours old. This makes the root-only items it lists (a sudoers drop-in no
  package installed, say) readable by your group, so it is only used when
  your primary group is yours alone; if it is shared with other accounts,
  root checks run only with `sweep --root`. The sandbox limits what a bug
  in the collector could change; it does not contain it: a process that is
  root and may read every file and every other process's memory
  (`CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`) has the secrets of the whole
  machine within reach if it is taken over.

The user unit gives up what the sweep and the AI reviewer it starts do not
need (gaining privileges, making set-id files, real-time priority, another
system-call interface). It cannot be given a read-only system the way the
collector is: in a user unit that puts the sweep into a user namespace of
its own, where every file of root's reads as nobody's, and the sweep could
no longer tell root's files (the list of allowed items, the root checks'
results) from anyone's.

Without root checks (declined, or not answered yet) every sweep is
incomplete and says what it could not check, and the bar shows the sweep as
not fully on. `protect --off` turns both timers off and keeps your answer.

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

**Working through what it finds.** A sweep flags what it cannot vouch for,
and some of that will be yours on purpose: a wrapper in `~/.local/bin`, a
keybinding that starts your own tool, an alias. Look at each one, then
either fix it or tell Guardian you know it:

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
`omarchy-guardian ask <id>` that opens your agent on it. Use it to go
through the list with your agent without waiting for the daily sweep.

- Use the path exactly as the sweep prints it, with `~/` for your home
  (quoted, so the shell leaves the `~` alone).
- An allow covers the file's current content and what the live checks saw
  about it. If the file changes, or the same program starts reading the
  keyboard, listening on the network or running with extra rights, it is
  shown again and the daily sweep notifies about it.
- Allowing a file stops its alerts, including the AI's, so a sweep with
  only allowed items comes back clear. It does not change the file or make
  what it runs safe: allow what you have read and meant to have.
- Items only root can read (in `/root`, `/etc/sudoers.d`) can be allowed
  once the daily root checks have run (root checks allowed in `protect`);
  `sweep allow` uses their latest results.
- What cannot be read at all (a program that exists only in memory, a
  deleted file) cannot be allowed; it stays listed while it runs. Nor can
  what overrides Guardian's own units, or an item whose commands were not
  all followed.
- Every allow is kept in one list only root writes
  (`/var/lib/omarchy-guardian/sweep/allowed.json`), so `sweep allow` and
  `sweep forget` ask for the sudo password, for items in your home too. A
  program running as you can write any file of yours: were the list one of
  them, it could drop an autostart entry and allow it in the same breath.
  An item in a home is kept under the user id it was allowed for, so what
  you allow in your home says nothing about another account's file of the
  same name; `forget --all` drops the system's items and yours, not other
  accounts'.
- Guardian up to 0.7.18 kept the allows for your home in a file of your
  own (`~/.local/state/omarchy-guardian/sweep/allowed.json`). It no longer
  counts, and a sweep says how many entries it holds. `sweep allow
  --migrate` lists them and, after you say yes and give the sudo password,
  moves the ones whose files are still exactly what you allowed; the rest
  (changed, gone, or not allowable) are named and dropped with the old
  list. Read the list before you say yes: anything running as you could
  have added to it.
- What the scheduled sweeps have already told you about (`told.json`) is
  your own file too, since the sweep that writes it runs as you: a
  program already running as you can add to it and so quiet a
  notification for something new in your home or the system. The alert
  itself, and the bar, still show it.
- `--diff` compares with the last sweep. An item that could not be read
  then and can be now (the root checks arrived) is not a change by
  itself, unless it now raises an alert; it is judged like any other in
  the full sweep.

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

You can also pick the model used for both (Claude Code models are listed and
suggested when `claude` is installed, otherwise OpenCode's), turn on every
install gate at once (*Protect everything*), test the reviewer (`t`), or reset
to the defaults.

Press `e` for **expert mode** (or start there with `tui --expert`), which
has every setting:

| Tab | What it changes |
|---|---|
| Profiles | the profile for your own sources (user file) and for the pacman gate (system file) |
| Sources | every knob of every source class; pacman-enforced classes in the system file, the rest in the user file |
| AI | model, input size and call limits for your sources and for the pacman gate, review-memory limits, official repositories |
| Integrations | turn the pacman hook, the yay AUR gate, the theme & plugin gate, the theme & plugin commands on PATH, the Omarchy menu entry, the bar widgets and the system sweep on or off |
| Maintenance | show and check the effective settings, edit either file in `$EDITOR`, see or forget the review memory, test the reviewer, run the guided setup |

Unset values show what they inherit and from where. Keys: `↑↓` move,
`Tab`/`1`–`5` switch tabs, `Enter` edit, `Space` cycle a choice, `x` reset to
inherit, `u` undo, `s` save, `e` back to simple mode, `q` quit. Every edit
is checked with the same parser that reads the files, so the app cannot save
a file Guardian would reject. The user file is written directly (a hand-written one is kept as
`config.toml.bak`, since comments are not preserved). The system file is
saved only after showing a diff, with `sudo`, like `setup` does. A file that
does not parse cannot be edited in the app; fix it with Maintenance › Edit.
Before Guardian first edits `~/.bashrc`, the Omarchy menu file or the Waybar
config and style, it keeps the file as it was beside it, as
`<name>.guardian-bak`; later edits leave that copy alone. What you turn on
or off here is recorded as your choice, so it raises no "protection
changed" notification.

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

That file is yours, so any program running as you can write it. Two things
keep that from quietly switching a gate off:

- A user file that is there and does not parse is not skipped. While it is
  broken, `makepkg-gate`, `guard`, `scan`, `sandbox` and `sweep` refuse with
  exit 2 and name the file and line, as the pacman gate does for the system
  file. (Skipping it would review at `standard` whatever stricter profile it
  holds.) `config check`, `config show`, `tui` and `setup` still work, to
  fix it.
- A user-level class set weaker than its profile (`ai` lower, `on_findings`
  or `on_ai_suspicious` on `warn` where the profile blocks, `confirm = false`
  under `local-only` with the AI off) still applies, and the bar counts it
  as a problem. To keep it, run `omarchy-guardian config acknowledge`: it
  lists those settings, shows the change to the system file and installs it
  with `sudo`:

  ```toml
  [acknowledged]                        # system file only
  weaker = ["aur.ai=off"]               # class.knob=value, as accepted
  ```

  Only root can write that file, so a program running as you cannot accept
  its own change, and an accepted value does not cover a lower one later.
  `cache`, `diff`, the model and the thinking level are choices, not
  weakenings. A weaker value in the system file itself needs no
  acknowledgement. Choosing the `local-only` profile in the user file is a
  protection level, not a weakening: it turns the AI review off for your own
  sources and asks before each install.

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
- `omarchy-guardian config acknowledge` — accepts, in the system file and
  with `sudo`, the user file's settings that are weaker than the profile.

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
| `LIMITED REVIEW` | 0 | nothing reviewable (a scriptlet-free pacman transaction); `guard` and `sandbox`, which start nothing then, exit 2 |
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
the full file list, so the model knows what else exists. A chunk is judged
on its own files, so a source that needs several is packed to keep together
what belongs together: the files of one directory, and a file with the
files it names, share a chunk where that takes no more chunks than packing
by rank would. Each chunk is also told which local rules matched in the
files of the other chunks (the rule, the file and the line, not the text),
and the report lists the files that name a file sent in another chunk. That
is the limit of it: a payload split over two files that land in different
chunks is seen by no single request, and Guardian does not ask the model
to report every call into another chunk, because any AI finding blocks and
large honest sources are full of such calls. A file is charged
what it takes in the request (a newline or a quote takes two bytes there, a
control or invisible character six and one outside the basic plane twelve,
a few percent more than the file's size for ordinary code). A
file larger than a chunk is split on line boundaries, each piece repeating
the end of the one before; a single line longer than a chunk is cut the same
way, so nothing is hidden by sitting exactly on a cut. The first chunk runs
alone; the rest run three at a time. A run that finds the AI unavailable (a
provider error, not a timeout) is retried once after two seconds, and so is
a reply that does not echo the run's nonce (models drop it now and then);
if it still fails, chunks not yet started are not attempted. A source that needs
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
  for `cache_days` (default 30). Reports mark such chunks `from cache`. "The
  same prompt" means its text: the key covers the system prompt, the
  message and the whole request with its instructions, so a reworded prompt
  never reuses an old verdict, whatever its version number says.
- **Diff review of upgrades.** A review becomes the approved baseline of that
  source when every chunk was `clear`, there were no gaps, and the decision
  is `CLEAR`. The next review of the same source is then sent as follows:
  changed files whole when they are small (up to 48 KiB: what a changed
  line switches on may be anywhere in the file), larger changed files
  whole too while together they fit half a request, and the rest as
  unified diffs with twenty lines of context against the baseline; new
  files and entry points whole; and unchanged files only as names in the
  file list, except the files a new or changed file names, which are sent
  along while they fit half a request. Any unchanged text file counts,
  whatever it is (a test fixture, a build helper, a document), named by
  its name (`payload.c`, or `helper` for `helper.py`), by a path
  (`build-aux/run`), or by a glob or directory that covers it
  (`tests/*.dat`, `hooks.d/`); a short name without an extension, such as
  `run`, counts only as part of a path. When a named file does not fit,
  the review is done in full if that fits `max_chunks`; if not, it stays
  an upgrade review, and the model and the report are told which named
  files were not sent. If the upgrade does not fit in `max_chunks` with
  these extras, the changes alone are sent. What a
  change switches on in a file that is neither shown nor named this way
  is not seen in that review: it was reviewed when it was approved. Local
  rules and the dependency audit still read every file. A baseline only
  counts under the prompt (its version and its wording), model, variant
  and thinking level that approved it; after any of them changes, the
  next review is a full one. A baseline also ages: after five upgrades
  approved as diffs, or thirty days, since the source was last reviewed in
  full, the next review is a full one, and so is the first review after an
  update of Guardian from a version that did not keep that count.
  So is the review of a version in which a file Guardian does not read (a
  binary, a link) was added, changed or removed, of a tree with a skipped
  generated directory, and of a version in which a file other than a
  document was removed (or any file, when nothing else changed): what the
  unchanged text runs may no longer be what
  was approved. When binaries or links differ, the AI is told which. An
  image is the exception, so a new wallpaper costs no AI call: the file
  must be named as one (`.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`), not be
  executable, and be one whole image from its first byte to its last by
  that format's own structure (a file that only starts like an image, or
  has anything after it, does not count). It must also be plausibly
  nothing but a picture: only the chunks and segments its format defines,
  text and comments of at most 1 KiB each and 4 KiB together, other
  metadata of at most 64 KiB, a colour profile of at most 1 MiB and an XMP
  packet of at most 16 KiB, no block of text lines in its metadata, and no
  line anywhere that a shell would act on (a shell asked to run a PNG does
  run it). That last test is a heuristic over the file's bytes: now and
  then it takes a real picture for one, which costs a full review, and it
  cannot rule out every line a shell could run. Guardian still does not look at
  what an image shows, so this rests on the approved text not running
  files it was not sent, which its review is asked to report. A
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
  privilege escalation, disabled TLS verification (`curl -k`, `git
  http.sslVerify false`, `--no-check-certificate`, an unverified SSL context,
  ...) and likely credential exfiltration. Also reverse and bind shells (a
  shell wired to a socket, in a shell one-liner or built in Python, Perl, PHP,
  Ruby or awk), cryptocurrency miners and mining pools, turning off a
  protection of the system (a firewall, a security service, SELinux, or one
  of Guardian's own gates), and erasing shell history or system logs.
  Download-to-shell also covers a fetch piped into another interpreter
  (`| python`, `| perl`, `| node`, ...), behind a wrapper (`| timeout 5 sh`,
  `| xargs sh -c`) or grouped (`| { sh; }`). Identifier patterns respect word
  boundaries, so `retrieval(` and `model.eval()` do not match `eval(`. Making a Chromium-family sandbox
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
  `exec` or a process substitution, sends what a loop, a block or one of
  its own functions prints to a file (by a redirection, `tee` or `dd`), or
  runs a command's output (`eval "$(…)"`, `source <(…)`), since its
  messages may then run. A
  command continued over several lines (a trailing backslash, pipe or `&&`,
  or a pipe opening the next line) is also judged as the one line a shell
  reads, and a download saved to a file that the same file later runs or
  sources counts as download-and-run, also when one file downloads and
  another runs what it saved. A fetcher or a shell kept in a variable
  (`F=curl` … `$F … | $S`) is read as what it is. These rules read text,
  not meaning: a command assembled any other way is left to the AI
  review. A file a reviewed script runs or reads in (`sh ./data/x.png`,
  `. ./lib`, `python3 tool.py`) that Guardian could only hash makes the
  review incomplete: it runs, and nobody read it. A prose file a reviewed
  line runs (`sh ./README`) is checked by the command rules after all, even
  though prose is otherwise exempt. Two further checks read **every** text
  file, prose included: text addressed to a reviewer or an AI model that
  tells it what to conclude (an injected "ignore previous instructions", a
  made-up verdict, a chat-template control token), reported with an excerpt
  so a human can judge, while ordinary writing about AI tools stays quiet;
  and hidden or reordering characters — bidirectional controls that reorder
  text (the Trojan Source technique), invisible Unicode tag characters, and
  zero-width characters inside a name, command or path — which deceive the
  human and the AI reader without changing what a program does (writing
  systems that need these characters, such as right-to-left text and
  translation files, stay quiet). Prose, comments and messages are still
  sent to the AI review.
- **Network destinations:** literal HTTP(S) hosts in code and runtime config,
  flagging cleartext HTTP and hard-coded IP addresses. A host is also flagged
  when it is one commonly used to deliver or receive stolen data (a paste
  site, a chat webhook such as a Discord or Slack webhook path, a tunnel or
  request catcher, dynamic DNS, a `.onion` address or a link shortener), or
  when its name is made to read as another — a label mixing alphabets, or a
  punycode (`xn--`) label. A PKGBUILD's `url=` homepage (never fetched), XML
  namespace, DTD and schema identifiers are not destinations. URL paths,
  queries and credentials are never printed: the host reputation is judged
  from the path internally, without recording it.
- **Dependencies:** `Cargo.lock`, npm lockfiles, `poetry.lock`, `go.sum` and
  exactly pinned `requirements*.txt` are checked with the public OSV API (only
  package names and versions are sent). Advisory severities and summaries are
  fetched per advisory; ones OSV does not rate are shown as `UNRATED`. Any
  advisory blocks a gate. Unsupported lockfiles, manifests with dependencies
  but no lockfile (or one that lists no package at all), or
  an unavailable OSV API make the review incomplete.
- **AI review:** the reviewable text is sent, in chunks of up to
  `max_input_kib` (default 256 KiB, at most `max_chunks` per review; see
  [How the review scales](#how-the-review-scales)), to the OpenCode CLI **on
  stdin** (never in argv, which is size-limited and visible to other users)
  with every OpenCode tool and permission denied. The reply must echo a
  random per-run nonce that only exists in that input and is given after
  the source, so a reply that never saw the source, or stopped reading
  part-way, is rejected. The nonce shows the
  reply came from a model that was given this request; it cannot show how
  carefully the source was read. In the request, every invisible or
  text-reordering character of a file or a file name (control characters,
  zero-width and bidirectional marks, variation selectors, Unicode tag
  characters) is written as a `\u` escape: the model sees which character
  was there, none reaches it raw, and none can draw a line that looks like
  the end of the data. Nothing is removed or masked. The reply may also say
  that the content speaks to its reviewer (an instruction, a verdict, a
  nonce, a reason to stop reading, in a comment, a string, a document or a
  file name). Guardian then adds a high finding of its own and the review
  is not clear, even if the same reply says `clear`: a model that was
  talked into a verdict is not taken at its word. A reply without that
  field is read as before. Files that look sensitive by path (`.env*`, `*.env`,
  `*.tfvars`, SSH and cloud credentials, key files, names containing
  `secret`, `credential` or `token`) are withheld and make the review incomplete.
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
for `official` under `standard`, blocked everywhere else. A provider that
answers that the request is too long for the model is not unavailable:
that review is incomplete. Nor is one that refuses what it was sent (a
usage-policy or safety refusal, a content filter, a guardrail): a source
can be written to be refused, so that review is invalid and blocks in
every class. A network or login error, a rate limit and an overloaded
provider stay unavailable. A run that times out before the model starts
on the source is unavailable. One that times out after the model had it
is not, since a source can be written to keep a reviewer busy: that
review is invalid and blocks, except for the `official` class, whose
content nobody writing such a source chooses, where it counts as
unavailable. In `.git`, only the
`config` (checked locally for keys that make git run a command, such as
`core.fsmonitor`, filters and `!` aliases, and never sent to the AI; also
`config.worktree`) and hooks other than git's `.sample` files are reviewed.
Submodules kept under `.git/modules` are read the same way, nested ones
included (past six levels the review is incomplete), and so is a
directory laid out as a repository under another name: its `config` is
checked the same way, and is also reviewed like any other file (a build
could run it as something else) with the user and password of every
address in it taken out, and so is an `extraHeader` login
(`Authorization: basic …` that decodes to a plain `user:password`). Other
values are kept whatever their key is called, since a value can be code
or name what a file runs: another token written there (a bearer token,
say) is seen by the AI provider, and so is a password with characters
other than letters, digits and `._~%+=-:`.
A `.git` given as a file or a link, a linked `config`, hooks or submodules behind a link, a
`commondir` (which makes git read another directory's configuration and
hooks), and such a `config` that cannot be read make the review
incomplete: git would read them and the review cannot. A file that opens like a known binary format or a UTF-16 mark but is
plain lines of text is reviewed as text, and text with a NUL byte after
its first line is not passed over as binary: it makes the review
incomplete. A file with a UTF-16 mark is read as UTF-16 only where
that gives mostly ASCII text; otherwise it is read by its bytes, which for
UTF-16 text in another script means hashed only. A file that opens like a
known format and holds NUL bytes near its start is taken as that format
and only hashed, even if text follows; if a reviewed script runs or reads
it in, the review is incomplete (see above). A top-level `target`,
`node_modules` or `.venv` that carries its tool's marker file
(`CACHEDIR.TAG`, `.package-lock.json`, `pyvenv.cfg`…) is skipped unless
`--thorough` is given; the skip is listed under "Not reviewed", its file
count is part of the snapshot, and the review is then at best `WARNED`.
`vendor`, `dist` and `build` are shipped code and always reviewed.

External helpers are run by absolute path (`/usr/bin/curl`, `/usr/bin/bsdtar`,
`/usr/bin/pacman`, ...) with a timeout and bounded output. OpenCode is looked
up in the absolute entries of `PATH` for `scan`, `guard` and `sandbox`. The
pacman hook only accepts a root-owned `/usr/bin/opencode` or
`/usr/local/bin/opencode`, because it gates a root transaction and a
user-writable reviewer could be replaced by user-level malware. A reviewer
found on `PATH` is refused, with the reason, when it or its directory can be
written by group or others, or when it lies under `/tmp`, `/var/tmp`,
`/dev/shm` or your cache directory (also behind a link). OpenCode must
be configured with a working provider; source leaves the machine through that
provider.

The reviewer is given as little besides the request as its CLI allows.
OpenCode runs from a new, empty, private directory (not from `/usr`, which
packages write under), with the switches that stop it reading `AGENTS.md`,
`CLAUDE.md`, `CONTEXT.md` and `opencode.json` from its directory and the
ones above it, `~/.claude/CLAUDE.md` and Claude Code's skills, skills from
other tools' directories and its default plugins
(`OPENCODE_DISABLE_PROJECT_CONFIG`, `OPENCODE_DISABLE_CLAUDE_CODE` and its
`_PROMPT` and `_SKILLS` forms, `OPENCODE_DISABLE_EXTERNAL_SKILLS`,
`OPENCODE_DISABLE_DEFAULT_PLUGINS`), and without updating itself or
downloading language servers. Neither reviewer inherits `NODE_OPTIONS`,
`BUN_OPTIONS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `LD_PRELOAD`,
`LD_LIBRARY_PATH`, `LD_AUDIT` or `OPENCODE_PERMISSION`: they load code into
the reviewer, switch off its TLS checks or lift the tool denials, and a
review has no use for them. Variables that people do use, for a proxy,
Bedrock or Vertex, are kept, and the report names the ones that were set
(names only): `ANTHROPIC_BASE_URL`, `ANTHROPIC_BEDROCK_BASE_URL`,
`ANTHROPIC_VERTEX_BASE_URL`, `CLAUDE_CONFIG_DIR`, `OPENCODE_CONFIG`,
`OPENCODE_CONFIG_DIR`, `HTTPS_PROXY`, `ALL_PROXY`, `NODE_EXTRA_CA_CERTS`
and `SSL_CERT_FILE`.

What stays yours, and so in the hands of anything running as you: for
your own sources, OpenCode's global configuration in `~/.config/opencode`
(a provider's `baseURL`, a global `AGENTS.md`), and for every review the
credentials in OpenCode's data directory, including "wellknown" logins,
through which OpenCode fetches and merges configuration from that
server. System-wide settings cannot be switched off either: Claude Code
applies `/etc/claude-code/managed-settings.json` and
`managed-settings.d/*.json` whatever `--setting-sources` says, and
OpenCode merges `/etc/opencode/opencode.json` over the configuration
Guardian passes. When such a file exists the report says the reviewer
loads it. For the pacman gate, a file that sets an endpoint or base URL,
a key or credential helper, environment, hooks or plugins (Claude Code),
or providers, plugins, MCP servers, permissions, tools, agents,
instructions or commands (OpenCode), or that Guardian cannot read as plain
JSON, makes the review unavailable with that reason: Guardian cannot tell
an administrator's policy from a file a package left there.

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
becomes `--effort` directly. Claude Code has no flag that leaves out the
administrator's managed settings (`--setting-sources` covers user, project
and local settings only), so those still apply; see above for what Guardian
does about them.

For your own sources `claude` is found on `PATH`. The pacman gate, as with
OpenCode, only accepts a root-owned `/usr/bin/claude` or
`/usr/local/bin/claude`; a Claude Code installed in your home directory is
not used for it, and `pacman-hook --preflight` says so.

## Install (Arch Linux / Omarchy)

```sh
git clone https://github.com/gosumarchy/omarchy-guardian
cd omarchy-guardian
./install.sh
```

The installer checks for a Rust toolchain (rustup's `cargo` is fine), builds
and tests the package, installs it with pacman, makes sure there is an AI
reviewer (it offers `claude-code`), runs the guided setup on a first
install, turns every gate on with `omarchy-guardian protect` after showing
each step, and tests the reviewer with a malicious and a harmless sample.
It asks for sudo only for the steps that need it, and skips what is already
done. To upgrade: `git pull && ./install.sh`.

By hand, the same steps are:

```sh
cd packaging/arch
makepkg -fd                                   # -d: rustup's cargo is not a pacman package
sudo pacman -U "$PWD"/omarchy-guardian-*-x86_64.pkg.tar.zst
sudo pacman -S --needed claude-code           # the pacman gate's reviewer (or extra/opencode)
omarchy-guardian setup
omarchy-guardian protect                      # or: omarchy-guardian tui › Protect everything
```

`omarchy-guardian protect` turns on the pacman hook, the yay AUR gate, the
theme & plugin gate, the Omarchy menu entry, the bar widget (Waybar and/or
Omarchy's shell bar) and the daily [system sweep](#system-sweep), showing
each step and asking first (`--yes` skips the question, but never answers
whether the sweep's root checks may run); `protect --off` turns the three
install gates and the system sweep off the same way. It leaves the pacman hook off when the
pacman gate could not review with the current settings. `omarchy-guardian
test` runs the two-sample reviewer test from the terminal.

Installing the package activates nothing. The package ships its hook in
libalpm's own hook directory (`/usr/share/libalpm/hooks/`), which pacman
reads whatever `--hookdir` it is given, but the hook lets every transaction
through until root has turned it on: `enable-system-hook.sh` links the hook
into `/etc/pacman.d/hooks/` (the link is what turns it on; a hook of the same
name there takes the place of the packaged one, so it still runs once) and
adds the theme interceptor to the invoking user's `~/.bashrc`.

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

- pacman hooks (`usr/share/libalpm/hooks`, `etc/pacman.d/hooks`), sudoers and
  `doas.conf`, polkit rules and action policies, PAM rules, `ld.so.preload`
  and `ld.so.conf.d`;
- systemd units a package enables itself (`*.wants/`, `*.requires/`,
  `*.upholds/`), generators and presets, and every unit in a directory
  systemd reads ahead of `usr/lib/systemd`, where a unit stands in for the
  system's own of that name: `etc/systemd`, `usr/local/lib/systemd/system`
  and `user`, `usr/share/systemd/user` and `usr/local/share/systemd/user`;
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
- certificate authorities in `etc/ca-certificates/trust-source`;
- in `etc/skel`, the files that would run on their own in a new user's home
  (`.bashrc`, `.config/hypr`, `.config/autostart` and the rest of the sweep's
  user locations), not the whole tree.

For a package that is not from an official repository, shell completions and
functions (`usr/share/bash-completion/completions`, `etc/bash_completion.d`,
`usr/share/zsh/site-functions`, fish's `vendor_completions.d` and
`vendor_functions.d`) and `usr/share/ca-certificates/trust-source` are
reviewed too: an interactive shell, root's included, reads them in. For
official packages they are not, since hundreds ship a completion file and
the Mozilla trust bundle is a megabyte of certificates.

A text file of the package that the scriptlet or one of those files names is
reviewed with it: the script a hook hands to an interpreter
(`Exec = /usr/bin/sh /usr/share/pkg/run.sh`), a program a scriptlet calls
(`post_install() { /usr/lib/pkg/setup.sh; }`, or by a bare name the package
ships in `usr/bin`), a file a login script sources, a udev `RUN+=` program,
a cron command. Every word of the file is looked at, not only the first of
a command, and what the named files name is followed in turn, three files
deep and 500 files per package at most. A named file that is a compiled
program or other binary data is not read: it is listed as not reviewed, to
you and to the AI. A named text file over 2 MiB, or more files or steps than
those bounds, makes the review incomplete. A path a script builds at run
time (`cd /usr/lib/pkg && ./setup.sh`) is not found.

A package that ships a symbolic link in place of one of those directories
(`etc/cron.d -> /usr/share/x`) is refused: what the link leads to would be
read as that directory's files. The same goes for a link in place of a
unit's `.wants` or `.d` directory. A link to another of those directories
of the same kind, named exactly (systemd's `etc/xdg/systemd/user ->
../../systemd/user`), is fine. A file installed setuid or setgid root is a
local finding (privilege escalation) unless it is already installed that
way, or is the sandbox helper of a Chromium-based program (by its name, with
that program's runtime files beside it, outside the command directories;
like every compiled program, its content is not reviewed): it blocks a
package from a third-party repository or a local archive, and is a warning
for an official one under the `standard` profile. The same goes for the
other ways a package hands out rights without a scriptlet: a file with file
capabilities or an access control list (read from the archive itself, since
pacman restores them), a set-id file for another user or group, and a file
or directory under `/usr`, `/etc` or `/opt` that everyone (a sticky
directory aside), a user other than root, or a group other than root's may
write. Each is passed over when the installed file is already that way: for
file capabilities, when it has exactly the ones the package ships (access
lists are not read back, so those are said every time). A package that is
not from an official repository and brings a new file into a place whose
content cannot be reviewed and that every login, program or boot uses (a PAM
module in `usr/lib/security`, a library in `usr/lib/glibc-hwcaps`,
`etc/default/limine`, `etc/kernel/cmdline`, `boot/limine.conf`) gets the
same finding; official packages ship PAM modules, so those are let through.

A package that installs a file under `/run`, `/tmp`, `/dev`, `/proc`, `/sys`,
`/root` or `/home`, or lists one under `/bin`, `/sbin`, `/lib`, `/lib64`,
`/usr/sbin` or `/usr/lib64` (links into `/usr` on this system), is refused:
no package's files belong there, and a unit under `/run/systemd` or a key
under `/root/.ssh` would act with nothing looking at it.

An auto-run file that is a symbolic link to a file the package does not
ship (a sudoers drop-in linked to `/usr/lib/other/rule`) is reviewed as
the file it leads to: as another package of the same transaction ships
it, or as it is on this system now when root alone could have put it
there and may change it; at every link on the way there, what the
transaction puts in that place counts. An unchanged link is reviewed
again when the transaction replaces the file it leads to. A link to a
device (`/dev/null`, which masks a unit) or the kernel's own files is
only noted. A link to a file that neither has, one someone else can
change, or one the transaction puts there as something else, makes the
review incomplete.

The other way round counts too: when a package replaces a file that a
symbolic link already in one of those locations leads to (another package's
`etc/sudoers.d/a -> /usr/share/b/rule`, or a unit you enabled with
`systemctl enable`), the new content is reviewed as that link's file, unless
it is identical to what is installed. The links are read from the system
itself; in a directory only root can list (`/etc/sudoers.d`,
`/etc/polkit-1/rules.d`) they are read from pacman's record of the packages
that ship into it, so a link root made there by hand is not seen.

What the gate does not see: a package's other files are installed as shipped
and acted on by what is already on the system (a pacman hook, DKMS or a
systemd generator installed earlier reads the new package's files without a
review of them), a removal is not reviewed, and a unit a package ships but
that you enable yourself later is not reviewed then (the sweep lists it; its
later upgrades are reviewed, through the link that enables it).

On an upgrade, an auto-run file identical to the installed one is not reviewed
again, since it adds nothing new: a point release typically brings a handful of
changed files, not every unit and rule. A link that enables a unit counts as
identical only while the unit it leads to is. These files go to the AI review only;
the local pattern rules are written for scripts and would match the ordinary
content of these files. Binaries among them (generators, for example) are
listed as not reviewed. A file the reviewed ones name is passed over the
same way when it did not change and every file that names it is passed over;
one the scriptlet names is reviewed every time, since the scriptlet runs
anew. The rest of the payload is not reviewed.

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
  against another system than the one Guardian reads. With `--hookdir`
  pacman leaves out `/etc/pacman.d/hooks`, so the refusal comes from the
  hook in libalpm's own directory, which it always reads.

Each archive must still be the reviewed one when the review is over. Its
path must name the same file, with the size and the times of last write and
last change (the kernel's own, to the nanosecond) it had when it was first
read, and unless the file and every directory above it are root's alone
(pacman's cache), its SHA-256, taken before anything is read from it, must
match again after the AI review has returned: an archive in your own
directory rewritten in place during the AI's minutes blocks the transaction.
Hashing runs at about 175 MiB per second, so a 1 GiB archive adds some
twelve seconds for the two passes. What no hook can close is the moment
between the hook's exit and pacman opening the file again: keep archives you
install with `pacman -U` where only you and root can write, which the hook
also checks.

Guardian's own program, hooks and scripts may only come from the
`omarchy-guardian` package installed from a local archive (as `install.sh`
does) or an official repository, never from a third-party repository that
offers a package of that name: such a package is refused by its name alone,
whatever it ships, and so is one of that name from anywhere that no longer
ships Guardian's program and hook script (an empty "upgrade" would delete
the gate). A package named `claude-code` or `opencode` is refused the same
way unless it comes from an official repository or is named in `[pacman]
trusted_reviewer_packages`. A package that declares it replaces, conflicts
with or provides `omarchy-guardian` is refused, since pacman would remove
Guardian for it; one that claims the place of a reviewer package is refused
unless it could ship the reviewer itself. No package may ship what the
reviewer would read as its own instructions or settings: `etc/opencode`,
`etc/claude-code`, and `AGENTS.md`, `CLAUDE.md`, `CONTEXT.md`,
`opencode.json`, `.opencode` or `.claude` in `/usr` or `/`. A local archive
named `omarchy-guardian` is still taken at its word: build Guardian only
from a source you trust.

The AI review is told what is under review (the scriptlets and those payload
files) and what routine packaging looks like: capabilities or setuid on the
package's own files, system users, copying its own files into place, its own
services, sockets and device rules, and privileges that only apply once an
administrator opts in (a dedicated, initially empty group, or a boot
credential). The package's text files that a scriptlet or payload file
names are supplied and judged with it. Files that are not supplied (a
compiled program, a file another package provides, one the scriptlet only
tells you to run), and how the package's own programs authorize requests,
are out of scope and not grounds for an inconclusive verdict. It still flags
downloading or running code from
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
   as facts. A package with fewer than 5 votes is also held against known
   names: the official packages in pacman's own databases on this machine,
   and one AUR search (again only the name is sent). A name that is a
   known one with another ending (`-bin`, `-git`, `-patched`, `-patch`,
   `-fixed`, `-fix`), or a letter or two from one, is flagged; AUR malware
   has arrived under such names (`firefox-patch-bin`). The one search finds
   a look-alike of an AUR package only when the names share their first two
   thirds. When the AUR cannot be reached, the build goes on, and both you
   and the AI are told that the signals are missing, not that they are
   fine. The package's history in its AUR repository is not read: that
   would mean running git in the build directory, which Guardian never
   does.
2. **The recipe.** The PKGBUILD, install scripts, patches and other AUR files
   are reviewed as `guard --class aur --thorough --exclude src --exclude pkg`
   would. The AI is told that upstream sources are reviewed in the next
   step, that prebuilt binaries cannot be reviewed by anyone, and what
   routine packaging looks like. A PKGBUILD's `url=` and `source=` entries
   are declarations, not network requests, for the local rules, unless they
   run a command.
3. **Sources**, for every call but one that only prints information
   (`--packagelist`, `--printsrcinfo`, `--version`, `--help`); generating
   checksums (`-g`) downloads the sources, so it is covered.
   Only now, with the recipe reviewed, `makepkg --printsrcinfo` lists the
   sources:
   - an unverified download over `http://` or `ftp://` blocks the build,
     since anyone on the network path can replace it. That holds for a
     call that builds from sources extracted earlier (`--noextract`) too;
     only a call that downloads and stops, such as `-g` to generate the
     missing checksum, is warned;
   - a git (or other VCS) source not pinned to a commit, or an unverified
     download over HTTPS, is a warning.
4. **Upstream code.** If the call extracts the sources, the gate first
   fetches and extracts them itself, in two makepkg runs inside a
   Bubblewrap sandbox (the system read-only, your home directory empty
   apart from makepkg's own configuration):
   - *Listing the sources* (`makepkg --printsrcinfo`). This reads the
     PKGBUILD, whose top-level code can run anything, so it gets no
     network and nothing of yours to write to: the recipe's directory is
     read-only. makepkg's build and download directories are given names
     made up for the run, and a recipe that has changed either by the end
     of it is refused. What the recipe prints while it loads is kept out
     of the listing, and a listing that is not shaped as makepkg prints
     one (text before its first line, a second package base, a line of
     another form) is refused. Sources are read from the package base's
     section only.
   - *Fetching them.* The PKGBUILD does not run here at all. makepkg is
     given a recipe Guardian writes from that listing: the sources, their
     checksums, what not to extract and the signing keys, each as quoted
     text, and no code. It downloads, verifies and extracts as it would
     for the real recipe, with the network on, a copy of your public gpg
     keyring (for source signatures; never the private keys), and write
     access only to the recipe's directory and the build and download
     directories your makepkg configuration names. An existing `src/` is
     removed first.

   So in this step the recipe's code only runs where it has no network
   and can write nothing but scratch files that are thrown away, upstream
   code does not run at all, and what is reviewed is what makepkg
   extracted from the downloads the build will use. This holds for the
   call that extracts. A helper such as yay first makes a call that only
   downloads and verifies (`--verifysource`): there the real makepkg reads
   the recipe, and runs its `verify()`, as you, with the network, after
   the review of the recipe's text alone (steps 1 to 3). Guardian refuses:
   - a source kept under a name that is a path (`a/b::…`, `../x::…`),
     which makepkg would write outside the downloads;
   - a version-control source whose checkout already exists, in the
     recipe's directory or the download directory, and is not a plain git
     mirror as makepkg makes one (other configuration, hooks, or another
     tool's checkout): makepkg would run that tool inside it. Remove the
     directory to fetch the source afresh;
   - a recipe of an AUR package whose `pkgbase` is not that package;
   - fetching into a build directory that is, or contains, your home
     directory, `/usr`, `/etc` or the temporary directory.

   A source that needs your SSH keys (`git+ssh://`) cannot be fetched in
   the sandbox: the fetch fails and the build is blocked.

   The fetch has the network, so it can reach services on this machine and
   your local network like any download.

   **A recipe can tell that it is only being listed.** The listing run is
   made to look like an ordinary one as far as that is cheap: makepkg is
   called on a file named `PKGBUILD` in the recipe's directory, no
   variable of Guardian's is in its environment, and the package directory
   is one a user's own setting could name. A recipe that looks can still
   tell: there is no network, its directory is read-only, the home is
   empty, and the file it is loaded from is a copy in the temporary
   directory. So the listing alone proves nothing about the build, which
   loads the recipe again. Guardian therefore reads the recipe's text for
   how it arrives at its sources, checksums, `noextract`, signing keys and
   makepkg's directories, and sorts it into one of three:
   - *Written out.* Each array is set once, at the top level, in plain
     words, with at most variables the recipe itself sets to plain text
     (`$pkgname`, `$pkgver`, `$_commit`, `$url`). The listing must then
     give exactly those arrays, or the build is blocked as incomplete.
   - *Worked out the same way everywhere*: an expansion Guardian does not
     repeat (`${pkgver%.*}`), `+=`, an element set by its number
     (`sha256sums[2]=SKIP`), a `case` or test on `$CARCH` only, a loop over
     a written-out list. Nothing more is asked.
   - *Not followed*: set under any other condition (`[[ -w . ]] &&
     source=(…)`), in a function the top level calls, through `eval`,
     `printf -v`, `read`, `mapfile`, `declare`/`typeset`/`local`/`export`
     (`-n` included), `${name:=…}`, from a command's output or a variable
     the recipe does not set; or the recipe sources another file, sets a
     trap or an alias, exits early, sets `DLAGENTS`, defines a function
     named like a command, or uses quoting Guardian is not sure it reads
     as bash does. The reasons are printed with their lines, the AI is
     told as a fact, and you are asked on the terminal whether to go on.
     No terminal, or no yes, blocks the build (exit 2, NOT CONFIRMED). A
     yes is remembered for that exact PKGBUILD, so yay's further makepkg
     calls and a rebuild do not ask again; a changed PKGBUILD does.

   In a sample of 700 AUR recipes about 3 to 4 in 100 are asked about
   (sources set per architecture with `if`, checksums taken from a
   command, `eval`, `DLAGENTS`). This reading is not a shell: text that
   bash reads otherwise than Guardian does could still hide an assignment,
   and the recipe is reviewed by the AI as well.

   What Guardian extracted is remembered (every file and download with
   its hash). A later call for the same build that does not extract
   (`--noextract`, yay's build call) is held against it before makepkg
   starts: a download that is new or not the one Guardian fetched blocks
   the build, and so does a source directory that is still the one
   Guardian made although the build was to clean and extract it again
   (`-C`): the build's own extraction and `prepare()` then ran somewhere
   else. Files that are new or changed in `src/` (what the build's own
   extraction, `prepare()` and `pkgver()` left) are reviewed before other
   code, and you and the AI are told how many there are. This catches a
   recipe that listed one thing and built another only after its
   `prepare()` and `pkgver()` ran on what it really fetched: Guardian
   hands the call that extracts over to makepkg and cannot look in
   between. The build itself runs with `--holdver`, so it does not fetch
   newer VCS sources than were reviewed.

   The AI then reviews the
   upstream code under `src/`: all of it when its code is up to 1 MiB,
   otherwise its build files and scripts (makefiles, CMake, meson,
   `configure`, `setup.py`, `build.rs`, `package.json`, shell scripts…)
   first, then other code by depth, up to 1 MiB. Code that a build file
   names (`"postinstall": "node tools/a/b/gen.js"`, a makefile that runs
   `lua`, `ruby`, `awk` or `php` on a file, or reads one in with
   `include`) counts as a build file however deep it lies. Data and
   documentation (`.json`, `.md`, `.txt`…) are left out, and so is a file
   over 2 MiB that is not a build file or script (a bundled `.js`, say).
   Every file left out, for its kind or past the budget, is kept by name:
   if a reviewed line, or one of the recipe's own functions or install
   scripts, runs or reads in such a file, or a binary (`sh ./NOTES.txt`,
   `sh ./tool.bin`, `node big.js`), the review is incomplete. Dependency
   lockfiles and manifests (`package-lock.json`, `yarn.lock`,
   `pnpm-lock.yaml`, `Cargo.lock`, `go.sum`, `go.mod`, `requirements*.txt`,
   `poetry.lock`, `Pipfile.lock`…) are always read: Guardian scans each
   one itself, whatever its size, for addresses outside the ecosystem's
   registry, version-control and unencrypted addresses, install scripts
   and lines that point a dependency elsewhere, prints what it found and
   tells the AI in its own words; the file itself is sent too when it is
   up to 64 KiB (a larger one would use up the review). `node_modules`, `.venv`, CI and
   development-container directories are reviewed last. git's own objects
   are not source, but git and Mercurial run what their metadata says on
   the commands a build often uses (`git describe`): a `.git` whose
   configuration names a command (hooks defined there included) or that
   holds live hooks (its submodules under `.git/modules` included, and a
   repository laid out under another name), one given as a file or a
   link, one with a `commondir`, and an `hgrc` with hooks or extensions
   make the review incomplete (a checkout makepkg made has none of
   these, unless your own git template directory installs hooks). A file
   placed at the top of `.git` that git does not keep there, and every
   file in a `.svn`, `.hg` or `.bzr` directory, is reviewed like the rest
   of the sources. A file or directory whose name is not UTF-8 is read
   and reviewed like any other. An archive the build opens itself (listed
   in `noextract`, or found inside the sources and named by the recipe or
   given by it to `bsdtar`, `tar`, `unzip`, `ar` and the like, such as the
   `data.tar.xz` of a `.deb`) is unpacked by Guardian first, beside
   `src/`, with `/usr/bin/bsdtar` in the same sandbox (no network, nothing
   writable but the directory unpacked into), and its files are reviewed
   like the rest, under the archive's path followed by `!`. Up to eight
   archives are unpacked, one inside another at most, each up to 2 GiB
   and 100,000 entries; one that holds a device file, exceeds that, or
   cannot be read by bsdtar is not unpacked, and the review is incomplete.
   An archive the recipe does not name stays packed and is named as not
   reviewed, up to five of them. The review looks
   for malicious intent in what runs during the build and in the program's
   own code, not bugs or vulnerabilities, and is told whether the recipe
   runs the test suite (`check()`). The upstream review is remembered as
   `aur-src:<package>`, so a new version is reviewed as a diff, unless a
   binary file in the unpacked sources was added, changed or removed (they
   are hashed; the downloaded archives themselves are not counted, since
   their names change with every version): then the code is reviewed in
   full and the AI is told which binaries differ. Guardian also keeps the
   hashes of the binaries of the last build it let through, with or
   without text beside them, and says which are new, changed or gone.
5. **Prebuilt programs.** Sources with no text to review are not a clear
   review. When a package is made of prebuilt programs (the recipe has no
   `build()` and its sources, or an archive it opens, hold programs), or
   the recipe's functions or install scripts name or run a program from
   the sources, Guardian says so plainly, for example `this package
   installs 3 prebuilt program(s) nobody reviewed, downloaded from
   github.com`, names them, and asks on the terminal. No terminal, or no
   yes, blocks the build (exit 2, NOT CONFIRMED). A yes is remembered for
   exactly those programs (their hashes) from those hosts, so yay's
   further makepkg calls and a rebuild of the same version do not ask
   again; a new version does. A source tree that is built and only carries
   a binary among its test data is not asked about. The question is asked
   on `/dev/tty`, after the review, and never replaces it.
6. **makepkg** starts with the original arguments.

What is not reviewed is reported: how many code files were left out, and
that data files were skipped. Prebuilt programs cannot be reviewed by
anyone; step 5 makes that your decision instead of a silent pass.
Dependencies a build downloads on its own during `prepare()` or `build()`
(cargo crates into `~/.cargo`, npm packages into `~/.npm`, Go modules into
`~/go`, pip, and the like) are **not reviewed**: they are not among the
sources. When the sources hold a manifest or lockfile, Guardian warns and
tells the AI so; the lockfile scan above covers where they come from, not
what they contain. On a call that only verifies sources (`--verifysource`), the
real makepkg runs the recipe's `verify()` on the downloads before any
upstream review: only the review of the recipe covers that function. The
gate refuses `--file` and `--dir` in any spelling makepkg accepts (with the
value attached, or shortened), and a shortened `--config`, since it reviews
the recipe in the working directory with the configuration it was given.

### Omarchy themes

Theme installs and updates are routed through Guardian in three places.

- **Commands on PATH** (*Theme & plugin commands (PATH)* in the Integrations
  tab). The package ships root-owned commands named `omarchy`,
  `omarchy-theme-install`, `omarchy-theme-update`, `omarchy-plugin-add` and
  `omarchy-plugin-update` in `/usr/lib/omarchy-guardian/bin`. `protect`
  writes `~/.config/uwsm/env.d/90-omarchy-guardian`, which uwsm reads after
  Omarchy's own session file and which puts that directory first on PATH for
  the whole graphical session and its service manager. Every caller that
  finds those commands by name then goes through Guardian: scripts,
  `bash -c`, zsh and fish, launchers, key bindings, the stock menu entries
  and AI agents. Guardian's `omarchy` hands theme and plugin installs and
  updates to Guardian and passes everything else straight to the real
  `omarchy` by its full path (which finds its commands in its own directory,
  not on PATH, so wrapping the four commands alone would miss `omarchy theme
  install`). It applies from the next login. Until then, and whenever the
  running session's PATH or its service manager's (`systemctl --user
  show-environment`) finds a stock command first, it reads "partly on".
- **The Bash interceptor** catches `omarchy theme install/update` typed in an
  interactive Bash, also in a shell whose PATH was reordered or that was not
  started from the graphical session (SSH, a console). It counts only as
  the exact line Guardian writes in `~/.bashrc`, at the top level, with no
  `return` or `exit` before it other than the usual "not interactive" line
  and nothing after it that unsets, redefines or aliases its functions.
  Guardian reads `~/.bashrc` line by line, not as a shell would: what a file
  sourced from it does is not seen.
- **Overrides in your Omarchy menu file**
  (`~/.config/omarchy/extensions/omarchy-menu.jsonc`, under your home
  whatever `XDG_CONFIG_HOME` says, as the menu reads it) point Install ›
  Style › Theme and Update › Extra Themes at Guardian by its full path.
  They count when they are the entries in effect: the menu takes the last
  entry of an item named twice, and ignores the whole file when it does not
  parse.

Turn them on from the TUI's Integrations tab (or *Protect everything*); the
theme & plugin gate shows as partial while only one of the interceptor and
the menu overrides is in place or in effect. Without the commands on PATH,
`omarchy theme` and `omarchy plugin` typed in another login shell (zsh,
fish) reach Omarchy directly, and the bar says so beside the gate.

Not covered: a caller that names the stock command by its full path
(`/usr/share/omarchy/bin/omarchy-theme-install`, `/usr/bin/omarchy-theme-install`),
a program that resets PATH or puts another directory in front, a session not
started through uwsm (SSH and console logins have the Bash interceptor
only), and a theme copied into `~/.config/omarchy/themes` by hand. The
session file is your own: a program running as you can remove it, which the
bar then shows and notifies about.

Themes are
cloned to a hidden staging directory and
reviewed; only the exact reviewed checkout is moved into place and applied.
Updates stage and review every Git-installed theme before replacing any.
Themes with local or ignored modifications, submodules, or unresolved Git LFS
files are refused.

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

Both are gated the same three ways as themes: Guardian's `omarchy`,
`omarchy-plugin-add` and `omarchy-plugin-update` first on the session's PATH
(every caller that finds them by name), the Bash interceptor in an
interactive Bash, and the menu override that points Setup › Plugins › Add
Plugin at Guardian. The same limits apply: a caller using the stock
command's full path, or a program that resets PATH, is not caught, and a
plugin copied into `~/.config/omarchy/plugins` by hand is not reviewed by
this gate. `omarchy plugin clone` copies Omarchy's own
built-in plugins and is not gated.

### Removal

```sh
yay --makepkg /usr/bin/makepkg --save -P --stats
sudo pacman -R omarchy-guardian
```

Removing the package removes the hook link, and with the package's files
the hook in `/usr/share/libalpm/hooks/`. A hook at the link's path that was
installed by hand and runs Guardian is moved to
`/etc/pacman.d/hooks/omarchy-guardian.hook.pacsave`, which pacman ignores.
To turn the pacman gate off without removing the package, remove the link
(`omarchy-guardian protect --off` does): the packaged hook then lets every
transaction through.
Turn the theme & plugin gate and the theme & plugin commands on PATH off in
the TUI or with `omarchy-guardian protect --off` before removing the package
(or delete the marked Guardian line from `~/.bashrc`, the `guardian-theme`
and `guardian-plugin` lines from the Omarchy menu file, and
`~/.config/uwsm/env.d/90-omarchy-guardian`) to stop theme and plugin
interception. The session file left behind after removal only names a
directory that no longer exists. The `<name>.guardian-bak` copies beside
`~/.bashrc`, the menu file and the Waybar config are the files as they were
before Guardian's first edit; delete them when you no longer want them.

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

The harnesses set `OMARCHY_GUARDIAN_NO_NOTIFY`, since their blocks are
expected: with it set no notification is shown and no browser opened. It
silences nothing else: the report of a block is saved and the bar shows it
all the same. The pacman hook's `--opencode-from-path` is for these
harnesses too, whose pacman is a script of yours; it is refused when the
pacman process belongs to root.

It needs `bwrap` 0.9 or newer, `bsdtar`, `pacman`, `git`, `flock`, `curl` and a
working `opencode`; it exits `77` when OpenCode cannot run, because every gate
is fail-closed on a failed AI review. To review with the Claude Code CLI and
your Claude login instead, set
`GUARDIAN_E2E_MODEL=claude-code/claude-sonnet-5-5` (the pacman checks that need
the AI are then skipped, because the pacman gate takes its model only from a
root-owned system config).

The system sweep has its own end-to-end suite: persistence the way PANIX and
real Linux malware set it up (enabled services, cron, udev, modprobe, the
dynamic linker, PAM, profile scripts, autostart, generators, pacman hooks,
NetworkManager dispatchers, initramfs hooks, a setuid shell copy, a replaced
setuid binary, Hyprland Lua, Omarchy hooks, `~/.local/bin` shadowing, a
launcher override, git and SSH, a program running from the cache) is planted
into throwaway `/etc` and `/usr` overlays and a throwaway `HOME`, and one
sweep must list every planted item and flag the plainly malicious ones;
`--diff` and `allow` are checked too. It needs `bwrap` 0.9 or newer and `jq`, and no AI
(the `system` class's AI review is off inside it):

```sh
cargo build --release
bash tests/e2e/sweep.sh
```

The AI review itself has an evaluation suite: install scriptlets, auto-run
package files, AUR recipes, themes, plugins and files already on a system
(found by `sweep`) that must come back clear, and attacks that must be
caught. An upgrade case holds two versions of one source: the first must be
approved, and the second is then reviewed against it. Run it after
changing a prompt, a scope or the model:

```sh
cargo build --release
bash tests/ai-eval/run.sh                 # or a filter: run.sh aur/block
```

Each case is reviewed three times (`RUNS=N` changes that) and gets a line
with its pass rate; the run ends with the rates of the block and the clear
cases and exits non-zero when any case passed less than every run. Some
block cases attack the reviewer itself: text addressed to it in a comment
or a README (with and without a harmful action beside it), an instruction
in invisible characters, a command put together from two files, and an
upgrade that switches on a file the approved version already had.
Every run starts with an empty review memory, so no verdict comes from the
cache. The pacman cases use the system config's model, the AUR, theme, plugin, upgrade and system
cases the user config's. A system case is judged by the AI's own medium or
high findings on its planted files, since the rest of the real system decides
the sweep's exit code; the host's own files no package vouches for are
reviewed alongside (and sent to the provider), so results can differ from
machine to machine.
