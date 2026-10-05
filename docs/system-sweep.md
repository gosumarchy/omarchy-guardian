# System sweep

`omarchy-guardian sweep` checks what already runs on its own on this machine:
the auto-run locations of the system and of your home, what runs now, and how
the machine was started. This page lists what it reads, how each item is
judged, what the root checks add, how the daily timers work, and how to work
through what it finds. What it cannot see is said where each part is
described.

## Contents

- [What it reads](#what-it-reads)
  - [Auto-run locations](#auto-run-locations)
  - [What is followed from a file](#what-is-followed-from-a-file)
  - [Where following stops](#where-following-stops)
  - [Programs ahead of the system's own](#programs-ahead-of-the-systems-own)
  - [More that decides what runs](#more-that-decides-what-runs)
  - [Accounts, keys and trust anchors](#accounts-keys-and-trust-anchors)
  - [Guardian's own units](#guardians-own-units)
- [What runs now](#what-runs-now)
  - [Programs with no file, or from a temporary directory](#programs-with-no-file-or-from-a-temporary-directory)
  - [Preloaded libraries](#preloaded-libraries)
  - [Packaged files compared with their package](#packaged-files-compared-with-their-package)
  - [Listeners](#listeners)
  - [Remote shells and relays](#remote-shells-and-relays)
  - [Keyboard, camera and packet sockets](#keyboard-camera-and-packet-sockets)
  - [Kernel modules](#kernel-modules)
  - [What hides](#what-hides)
  - [Debuggers and eBPF](#debuggers-and-ebpf)
  - [Set-id files and capabilities](#set-id-files-and-capabilities)
- [How the machine was started](#how-the-machine-was-started)
- [How each item is judged](#how-each-item-is-judged)
- [What goes to the review](#what-goes-to-the-review)
  - [What is kept from the AI](#what-is-kept-from-the-ai)
  - [What is sent](#what-is-sent)
  - [What is taken out of a file that is sent](#what-is-taken-out-of-a-file-that-is-sent)
  - [After an upgrade](#after-an-upgrade)
- [Root checks](#root-checks)
  - [What root reads and hands back](#what-root-reads-and-hands-back)
  - [Paths a user can point root at](#paths-a-user-can-point-root-at)
  - [The one thing told of a root-only file](#the-one-thing-told-of-a-root-only-file)
  - [Other accounts](#other-accounts)
  - [What is read of `/etc/shadow`](#what-is-read-of-etcshadow)
- [On a schedule](#on-a-schedule)
  - [The two timers](#the-two-timers)
  - [Consent](#consent)
  - [The collector's sandbox](#the-collectors-sandbox)
  - [The results file](#the-results-file)
  - [When the sweep itself breaks](#when-the-sweep-itself-breaks)
- [Working through what it finds](#working-through-what-it-finds)
  - [What an allow covers](#what-an-allow-covers)
  - [What cannot be allowed](#what-cannot-be-allowed)
  - [Where the list is kept](#where-the-list-is-kept)
  - [Lists from older versions](#lists-from-older-versions)
  - [Records that are your own](#records-that-are-your-own)
- [Rule ids](#rule-ids)

## What it reads

The sweep works the way Objective-See's KnockKnock does on macOS: it reads
every auto-run location the pacman gate knows, a few more that only the sweep
reads, the same kinds of place in your home, and what the sections further
down add.

### Auto-run locations

"Gate and sweep" means the pacman gate reviews a file a package ships there
and the sweep looks at what is there now; "sweep only" means the gate does not
review what is there, and the sweep alone reads it. The home column is the
sweep's alone (the pacman gate reads those files only where a package ships
them into `/etc/skel`).

| Area | System | Home | System column read by |
| --- | --- | --- | --- |
| systemd units | Units, the links that enable them (`.wants`, `.requires`, `.upholds`) and drop-ins in `/etc/systemd/system`, `/etc/systemd/user`, `/etc/xdg/systemd/user`, `/etc/systemd/system.control`, `/etc/systemd/system.attached`, `/usr/local/lib/systemd/system`, `/usr/local/lib/systemd/user`, `/usr/local/share/systemd/user` and `/usr/share/systemd/user`; in `/usr/lib/systemd/system` and `/usr/lib/systemd/user` the enable links and drop-ins; presets (`system-preset`, `user-preset`); the manager configuration (`/etc/systemd/system.conf`, `user.conf`, and `*.conf.d` drop-ins under `/etc/systemd` and `/usr/lib/systemd`) | `~/.config/systemd/user`, `~/.config/systemd/user.control`, `~/.local/share/systemd/user`, `~/.config/systemd/user.conf` and `user.conf.d` | gate and sweep |
| Podman quadlets | `/etc/containers/systemd` | `~/.config/containers/systemd` | sweep only |
| systemd generators | `system-generators`, `user-generators`, `system-environment-generators` and `user-environment-generators` under `/usr/lib/systemd`, `/etc/systemd` and `/usr/local/lib/systemd` | | gate and sweep |
| Sleep and shutdown hooks | `system-sleep` and `system-shutdown` under `/usr/lib/systemd` and `/etc/systemd` | | gate and sweep |
| Boot-time files | `tmpfiles.d` and `sysusers.d` under `/usr/lib` and `/etc` | | gate and sweep |
| Mounts and unlocking | `/etc/fstab`, `/etc/crypttab` | | sweep only |
| Kernel modules and parameters | `sysctl.d`, `modules-load.d`, `binfmt.d` and `modprobe.d` under `/usr/lib` and `/etc` | | gate and sweep |
| udev rules | `/usr/lib/udev/rules.d`, `/etc/udev/rules.d`, `/usr/local/lib/udev/rules.d` | | gate and sweep |
| Boot loader: what entries and the kernel command line are built from | `/usr/share/limine-entry-tool.d`, `/etc/limine-entry-tool.d`, `/etc/cmdline.d` | | gate and sweep |
| Boot loader: its own configuration | The Limine config (`/boot/limine.conf`, `/etc/default/limine`), `/etc/kernel/cmdline` | | sweep only |
| Initramfs and kernel install hooks | initcpio (`/usr/lib/initcpio/hooks`, `install` and `post`, `/etc/initcpio`), `/etc/mkinitcpio.conf`, `/etc/mkinitcpio.conf.d`, `/etc/mkinitcpio.d`, `kernel/install.d` under `/usr/lib` and `/etc`, DKMS build configuration (`/usr/src/*/dkms.conf`) | | gate and sweep |
| Dynamic linker and Python start-up | `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d`, `/etc/nsswitch.conf`; Python's `.pth`, `sitecustomize.py` and `usercustomize.py` files in `/usr/lib/python*/site-packages` and `/usr/lib/python*/sitecustomize.py`, which every Python program runs at start | Your own `.pth`, `sitecustomize.py` and `usercustomize.py` in `~/.local/lib/python*/site-packages` | gate and sweep |
| Preferred libraries | Libraries in `/usr/lib/glibc-hwcaps` | | sweep only |
| Login (PAM) | `/etc/pam.d`, `/usr/lib/pam.d`, `/etc/security` | | gate and sweep |
| PAM modules | `/usr/lib/security` | | sweep only |
| sudo | `/etc/sudoers`, `/etc/sudoers.d`, `/etc/sudo.conf`, `/etc/doas.conf` | | gate and sweep |
| Polkit | Rules in `/etc/polkit-1/rules.d` and `/usr/share/polkit-1/rules.d`, actions in `/usr/share/polkit-1/actions` | | gate and sweep |
| Pacman hooks | `/usr/share/libalpm/hooks`, `/usr/share/libalpm/scripts`, `/etc/pacman.d/hooks`, `/etc/pacman.conf` | | gate and sweep |
| Shell start-up files | `/etc/profile`, `/etc/profile.d`, `/etc/bash.bashrc`, `/etc/bash.bash_logout`, `/etc/zsh`, `/etc/fish`, `/usr/share/fish/vendor_conf.d`, completions and functions (`/etc/bash_completion.d`, `/usr/share/bash-completion/completions`, `/usr/share/zsh/site-functions`, `/usr/share/fish/vendor_functions.d`, `/usr/share/fish/vendor_completions.d`), makepkg's configuration and library (`/etc/makepkg.conf`, `/etc/makepkg.conf.d`, `/usr/share/makepkg`), what uwsm sources (`/usr/share/uwsm/env.d`, `/usr/share/uwsm/plugins`, `/etc/xdg/uwsm`), `/etc/inputrc` | `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.bash_logout`, `~/.profile`, `~/.zshrc`, `~/.zprofile`, `~/.zshenv`, `~/.zlogin`, `~/.zlogout`, fish's `config.fish`, `conf.d`, functions, completions and saved variables (`fish_variables`) under `~/.config/fish`, what uwsm sources (`~/.config/uwsm`), `~/.makepkg.conf`, `~/.config/pacman/makepkg.conf`, `~/.inputrc` | gate and sweep |
| Session environment | `/etc/environment`, `environment.d` under `/usr/lib` and `/etc` | `~/.config/environment.d`, `~/.pam_environment` | gate and sweep |
| Scheduled jobs | cron (`/etc/crontab`, `/etc/anacrontab`, `/etc/cron.d`, `/etc/cron.hourly`, `cron.daily`, `cron.weekly`, `cron.monthly`, `/var/spool/cron`), `at` jobs (`/var/spool/atd`, `/var/spool/at`), logrotate (`/etc/logrotate.conf`, `/etc/logrotate.d`) | | gate and sweep |
| Autostart, login screen and sound server | `/etc/xdg/autostart`, `/etc/X11/xinit/xinitrc.d`, the login-screen configuration (`/etc/sddm.conf`, `/etc/sddm.conf.d`, `/usr/lib/sddm/sddm.conf.d`, `/usr/share/sddm/scripts`, `/etc/greetd`), the sessions the login screen offers (`/usr/share/wayland-sessions`, `/usr/share/xsessions`), PipeWire and WirePlumber configuration (`/usr/share/pipewire/*.conf.d`, `/etc/pipewire`, `/usr/share/wireplumber/*.conf.d`, `/etc/wireplumber`) | `~/.config/autostart` (`.desktop` files), the X session files (`~/.xprofile`, `~/.xinitrc`, `~/.xsession`, `~/.xsessionrc`), the Waybar configuration (`~/.config/waybar/config`, `config.jsonc`) | gate and sweep |
| D-Bus services and policy | `/usr/share/dbus-1/system-services`, `/usr/share/dbus-1/services`, `/usr/share/dbus-1/system.d`, `/etc/dbus-1/system.d` | Session services in `~/.local/share/dbus-1/services` | gate and sweep |
| Network hooks | `NetworkManager/dispatcher.d` under `/usr/lib` and `/etc` | | gate and sweep |
| SSH | `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d`, `/etc/ssh/ssh_config`, `/etc/ssh/ssh_config.d`, `/etc/ssh/sshrc` | `~/.ssh/authorized_keys`, `~/.ssh/authorized_keys2`, `~/.ssh/rc`, `~/.ssh/config`, `~/.ssh/config.d` | gate and sweep |
| Git | `/etc/gitconfig`, the hooks git copies into every new repository (`/usr/share/git-core/templates/hooks`) | `~/.gitconfig`, `~/.config/git/config` | gate and sweep |
| Hyprland | | `~/.config/hypr`: the Lua configuration (and what `exec_on_start` starts) and the `.conf` files | |
| Omarchy hooks | | `~/.config/omarchy/hooks` | |
| Programs ahead of the system's own | `/usr/local/bin`, `/usr/local/sbin` | `~/.local/bin`, `~/.cargo/bin`, and the other directories [read from `PATH`](#programs-ahead-of-the-systems-own) | gate and sweep |
| Browser | Policies (`/etc/chromium/policies`, `/etc/opt/chrome/policies`, `/etc/brave/policies`, `/etc/firefox/policies`), native-messaging hosts (`/etc/chromium/native-messaging-hosts`, `/etc/opt/chrome/native-messaging-hosts`, `/usr/lib/mozilla/native-messaging-hosts`), extensions (`/usr/share/chromium/extensions`, `/usr/lib/mozilla/extensions`), Firefox's `distribution` directory (`policies.json`) and default preferences (`/usr/lib/firefox/distribution`, `/usr/lib/firefox/defaults/pref`, `/usr/lib/firefox/browser/defaults/preferences`) | Flags files and native-messaging hosts (see [More that decides what runs](#more-that-decides-what-runs)) | gate and sweep |
| Editor | Vim's and Neovim's start-up files and plugin directories (`/usr/share/nvim/site/plugin`, `after/plugin`, `ftdetect` and `pack/*/start/*/plugin`, `/usr/share/nvim/runtime/plugin`, `/usr/share/nvim/sysinit.vim`, `/etc/xdg/nvim`, `/usr/share/vim/vimfiles/plugin`, `after/plugin`, `ftdetect` and `pack/*/start/*/plugin`, `/etc/vimrc`) | Editor start-up files and VS Code's `settings.json` (see below) | gate and sweep |
| Terminal and prompt | `/etc/tmux.conf` | Terminal, prompt and tmux configuration (see below) | gate and sweep |
| Developer tools | The system-wide `/etc/npmrc` and `/etc/pip.conf` | mise, npm, pip, cargo, gem, yarn, bun, conda, Go, curl and wget configuration (see below) | sweep only |
| Trust anchors | Certificate authorities in `/usr/share/ca-certificates/trust-source` and `/etc/ca-certificates/trust-source` | | gate and sweep |
| Trust anchors and name resolution | Certificate authorities added in `/usr/local/share/ca-certificates`, `/etc/hosts` | | sweep only |
| App launchers and Flatpak | System-wide Flatpak overrides (`/var/lib/flatpak/overrides`) | `mimeapps.list` and launchers in `~/.local/share/applications`, `~/.local/share/flatpak/overrides` (see below) | sweep only |

For a package from an official repository the gate leaves the completion and
function directories and `/usr/share/ca-certificates/trust-source` unreviewed
(hundreds of packages ship a completion file); the sweep looks at them either
way.

In the home not every file of a location counts: in `~/.config/hypr` only
`.lua` and `.conf` files (others are followed where one of those names them);
in `~/.config/autostart` only `.desktop` files; Omarchy hooks but for
`*.sample`; in `~/.local/share/applications` only `mimeapps.list` and a
launcher that takes the name of one in `/usr/share/applications` (noted as
replacing it); in `~/.local/bin`, `~/.cargo/bin` and `/usr/local/bin` only
programs named like a system command. Old password hashes
(`/etc/security/opasswd`) are never read.

### What is followed from a file

The sweep follows links and what each file runs, so a trusted service running
a replaced binary, or an interpreter running a script, is checked too. It
follows:

- past wrappers (`sudo -u`, `doas`, `uwsm app --`, `systemd-run`, `env`,
  `timeout`, `flock`, `nice`, `nohup`, `setsid` and the like);
- into each command a shell is handed with `-c`, and each command of a line a
  shell runs joined with `;`, `&`, `|` or a line break (a crontab's, say), the
  first 1024 of each;
- into the files a shell start-up file reads in with `source` or `.` and the
  programs its statements start by a path (on lines up to 64 KB);
- the start-up files zsh reads from the directory a `ZDOTDIR=` line names;
- a unit's `EnvironmentFile=`;
- the files and directories a sudoers file includes;
- a Hyprland `.conf`'s `exec` and `exec-once` lines (and their variants),
  `source`, `plugin` and `bind … exec` lines, with the commands hypridle,
  hyprlock and their like run (`on-timeout`, `on-resume`, `lock_cmd`,
  `before_sleep_cmd` and so on).

A unit's command that runs over several lines (ending in `\`) is read as one,
and `%h`, `%E`, `%S`, `%C` and `%L` (and `%t` in a system unit) are written
out. `~`, `$HOME`, `$XDG_CONFIG_HOME` and `$XDG_DATA_HOME` at their default
places and a path a start-up file puts in a variable of its own
(`TOOLS=~/opt/tools`, then `$TOOLS/run`) are understood, other variables are
not. A Hyprland `source` with `*` or `?` in its last part is followed to the
files it matches (up to 1024).

A bare command name in an auto-run file is looked for along the list of
directories described under [Programs ahead of the system's
own](#programs-ahead-of-the-systems-own), first where a shell would look
first, and every place it is found in is judged.

### Where following stops

The file itself is always reviewed as text; what is not followed is only the
extra look at the program it names. The limits:

| Limit | Value |
| --- | --- |
| Commands on one line a shell runs | 1024 |
| Files one pattern stands for | 1024 |
| A line of a start-up file looked through for programs | 64 KB |
| One command line split into its commands (a longer one is taken as a single command) | 64 KB |
| Links in a chain | 8 |
| Scripts in a chain, each started by the one before | 3 |

Where one of these limits is reached, the item says so in its notes and
cannot be allowed, since an allow would vouch for commands nobody followed;
and where the item's text is not reviewed either (a file kept from the AI),
the sweep is **incomplete**.

Never followed: a path under `/dev`, `/proc` or `/sys` (under `/dev/shm` and
`/run` only a regular file is), and the pattern of a shell `case` branch
(`/*)`), which is matched, not run.

A file is always read as the kind of file it is: a unit as a unit, a udev
rule as a udev rule, a table of cron jobs as that, whatever its first line (a
`#!/bin/sh` there is a comment to systemd, udev, cron and SSH).

A shell script that no repository package vouches for (tier `unknown`,
`user-built`, `edited` or `modified`) is looked through like a shell start-up
file as well, wherever the sweep found it: a unit's wrapper, a cron script, an
Omarchy hook, a script another script starts. The programs it starts by a path
and the files it sources are collected and judged in turn, with the same
limits, so a service's wrapper in your home that launches a second stage from
`~/.cache` has that second stage listed. A file counts as a shell script:

- by its first line: `sh`, `bash`, `dash`, `zsh`, `ksh`, `ash` or `mksh`, also
  through `env` (`env -S`, `env -u VAR`) or `busybox`, and after a byte-order
  mark;
- without such a line, by its name (`x.sh`);
- or because the command that runs it is a shell (`ExecStart=/bin/sh
  /home/u/bin/run`), whatever it is called.

Chains are followed three scripts deep, counted along the shortest way to each
script; the fourth is reviewed as text, says that what it runs was not
followed, and cannot be allowed. Shell start-up files and what they source are
not bounded this way: they are followed as far as they lead, as before. There
is no cap on the number of items a sweep collects.

What remains:

- a packaged script that is intact (or a copy of one) is not looked through,
  since thousands of them start packaged programs;
- scripts of other interpreters (Python, Perl, Node, fish) are reviewed as
  text only;
- inside a script, only a program in the place of a command and named by a
  path is picked up: `bash /x/stage.sh`, `exec python3 /x/s.py`, a program
  named by a bare name or handed over as an argument are not;
- as root nothing is followed from a script the collector reached by
  following.

An allowed script is looked through like any other: what it starts is an item
of its own.

A file or directory whose name is not valid UTF-8 cannot be checked, and
shells, udev and pacman read such names all the same: the sweep says so and is
**incomplete** (exit 2). It is incomplete too when a location holds more than
20,000 files or goes more than six directories deep, when a pattern of the
catalogue matches more than 500 files, when there are more than 2,000,000
files to look through for setuid programs, when `getcap` fails or times out,
when a package's record cannot be read, and when the root checks found more
than 5,000 items.

### Programs ahead of the system's own

A program in a directory that comes before `/usr/bin` on `PATH` runs whenever
its name is typed.

**Which directories.** Which directories those are is read from the real
`PATH`s: the one the sweep runs with, the systemd user manager's (`systemctl
--user show-environment`), and the `PATH` lines of everything a login, a shell
or the session reads: your shell start-up files and the files they `source`
(three levels deep, 256 files in all), `/etc/profile` and `/etc/profile.d`,
fish's `conf.d`, `environment.d` (yours and the system's),
`~/.pam_environment`, uwsm's `env` files and Hyprland's `env` lines (Omarchy's
own included). A line counts wherever on it the statement stands (`[ -d ~/.x ]
&& export PATH=~/.x:$PATH`, inside an `if`, after `declare -x` or `typeset
-x`, among other assignments), in the bash, zsh, fish and csh forms. A line
that sets `PATH` from a command (`PATH=$(…)`) cannot be followed: the file's
item says so in a note, since the directories it adds are not watched. Where
mise is installed or turned on (`mise activate`), its shims and the
directories of what it installed are on the list too, as they are in an
interactive shell. The usual directories (`~/.local/bin`, `~/.cargo/bin`,
`~/bin`, mise's shims, the Go, Bun, Deno, pnpm, npm and Nix directories) are
added where no `PATH` that was read puts them behind `/usr/bin`; a directory
that is ahead of `/usr/bin` in any one of these is watched.

**What is listed.** In each directory on the list that someone other than root
can write, the programs named like a command in `/usr/bin` or in Omarchy's
`bin` are listed, and any named like the commands below.

**What is a finding.** One named like a command that asks for a password,
fetches or installs (`sudo`, `su`, `doas`, `pkexec`, `run0`, `ssh`, `scp`,
`git`, `gpg`, `pacman`, `yay`, `paru`, `makepkg`, `systemctl`, `loginctl`,
`passwd`, `curl`, `wget`, `bash`, `sh`, `zsh`, `fish`, `omarchy`,
`omarchy-guardian`) is a high finding in any of these directories, where the
system has a command of that name (in `/usr/bin` or Omarchy's own `bin`) and
the file is not a packaged one or a copy of one. `python`, `python3`, `node`,
`claude`, `opencode` and the `omarchy-*` commands are one too, unless a
version manager put them there: a mise shim (a link to mise itself, as trusted
as that mise) or a program in mise's install directory or `~/.cargo/bin` is
shown as `user-built` at most. A start-up file that puts the working directory
(`.`, or an empty entry) or a temporary or cache directory on `PATH` is a
finding on that file.

**Guardian's own session file.** The file `protect` writes for the graphical
session (`~/.config/uwsm/env.d/90-omarchy-guardian`) is Guardian's own while
it is byte for byte what `protect` wrote, and shown only with `--all`; with
anything else in it, it is a file like any other.

### More that decides what runs

These run nothing by themselves, so each has a plain local rule. Their text is
reviewed too, except where it is kept from the AI, which is said below.

- **Browser.** Browser flags (`~/.config/chromium-flags.conf`, `chrome-`,
  `brave-`, `code-` and `electron*-flags.conf`): an extension loaded from
  outside `/usr` and `/opt`, a remote-debugging port, a proxy, switched-off
  web security; browser policies in `/etc` that force an extension, a proxy or
  certificates; native-messaging hosts (Chromium, Chrome, Brave, Firefox),
  whose program is followed like any command.
- **Terminal and prompt.** The shell or command a terminal or prompt starts
  each time (alacritty, kitty with its `startup_session` and `watcher`,
  ghostty, foot, the `command` and `when` of a starship custom module, tmux's
  `run-shell`, `default-command` and `source-file`), followed like any
  command.
- **Launchers.** `mimeapps.list` and the launchers it names in
  `~/.local/share/applications`: one that opens web links (`http`, `https`,
  `text/html`) without a namesake in `/usr/share/applications` is a finding.
- **Flatpak.** Flatpak overrides that open the sandbox to the home or the
  host, or let an app talk to `org.freedesktop.Flatpak`.
- **Editor.** Editor start-up files (`~/.config/nvim/init.lua` and `init.vim`,
  `plugin/`, `after/plugin/` and `lua/`, `~/.vimrc`, `~/.vim/plugin`), and in
  the `settings.json` of VS Code and its forks (Code - OSS, VSCodium, Cursor)
  the settings that run a folder's tasks unasked, the environment and shell of
  its terminal (`terminal.integrated.env.*` with `LD_PRELOAD`, `PATH` and the
  like, `profiles`, `automationProfile`, `shellArgs`), `git.path`, a proxy,
  switched-off certificate checks and a program it is told to run from a
  temporary or cache directory (the list of installed extensions is not read).
  Of the terminal's environment only the variables that change what runs or is
  loaded count (`PATH`, `LD_PRELOAD`, `NODE_OPTIONS`, `PYTHONPATH`,
  `BASH_ENV`, `GIT_SSH_COMMAND`, `GIT_CONFIG_*`, a proxy and the like, or a
  compiler from outside the system's directories), not `EDITOR`, `PAGER` or an
  app's own; and a Python interpreter in a virtual environment a tool keeps
  under `~/.cache` (Poetry, uv, pre-commit) or `~/.local/share/virtualenvs` is
  a project's ordinary one.
- **`/etc/hosts` and `/etc/crypttab`.** In `/etc/hosts` (checked locally,
  never sent to the AI), a line for a host that updates, packages or the AI
  review come from (archlinux.org, omarchy.org, github.com, anthropic.com, the
  package registries) is a finding; a `keyscript=` in `/etc/crypttab` is one
  too.

**Developer tools.** mise's configuration (`~/.config/mise/config.toml`,
`~/.mise.toml`: what it sources, its hooks and tasks) and cargo's
(`~/.cargo/config.toml`: `rustc-wrapper`, `linker`, `runner`, a credential
provider, a replaced source or crate, a proxy, variables such as `LD_PRELOAD`
under `[env]`), whose commands are followed; `~/.npmrc`, pip's
(`~/.config/pip/pip.conf`, `~/.pip/pip.conf`, `~/.pydistutils.cfg`), gem's,
yarn's, bun's, conda's and Go's configuration, `~/.curlrc` and `~/.wgetrc`.

What is a finding there:

- a registry other than the usual one;
- a program the tool is told to run or code it is told to load
  (`script-shell`, `git`, `node-options --require`, `yarnPath`, `plugins`,
  `preload`, `-toolexec`, `CC`);
- a proxy;
- certificate authorities of the file's own or switched-off checks
  (`strict-ssl`, `trusted-host`, `insecure`, `GOINSECURE`, a wide
  `GOPRIVATE`);
- for pip, an index that is plain `http://`, a bare address, a name made to
  read as another, or a host data is dropped off at.

One that names a path in a temporary or cache directory, or an `http://`
address, says so, and each finding names its line.

What developers set every day is not a finding: a compiler or linker by its
name or from the system's directories (`linker = "clang"`, the same in
`rustflags`, `CC = "clang"` under `[env]`), the system's own certificate
bundle (`/etc/ssl`, `/etc/ca-certificates`, `/usr/share/ca-certificates`), and
for pip an index of a project's or a company's own over HTTPS
(`download.pytorch.org`).

What is kept from the AI: these files hold registry tokens, so like the SSH
and git files they are checked locally and never sent to the AI (mise's and
cargo's are reviewed, with secret-looking values taken out), and what is shown
is the key and, for an address, its host, never the rest of the value; so are
an editor's `settings.json` and fish's saved variables.

### Accounts, keys and trust anchors

Each of these is an item of its own, checked locally and never sent to the AI:

- every account with a login shell (a second account with user id 0, and a
  system account with a login shell and a password that works, are high
  findings);
- every member of a group that amounts to root (`wheel`, `sudo`, `root`,
  `docker`, `lxd`, `incus-admin`, `libvirt`, `disk`, `shadow`);
- every key in your `~/.ssh/authorized_keys` and `authorized_keys2` and in the
  files `AuthorizedKeysFile` in the server's configuration names, in your home
  or anywhere else (`/etc/ssh/keys/%u`, with `%u`, `%U`, `%h` and `%%` written
  out for the account; shown by type, SHA-256 fingerprint and comment, as
  `ssh-keygen -l` prints them, never the key);
- every certificate authority added in
  `/etc/ca-certificates/trust-source/anchors` or
  `/usr/local/share/ca-certificates`.

The files `TrustedUserCAKeys` and `AuthorizedPrincipalsFile` name are followed
like a command. Past 200 keys of one account the rest are one item ("N more
keys", with a hash that moves when they do), and a key file over 1 MiB, which
the SSH server reads all the same, is an item saying its keys are not listed:
both are findings, since neither is how a key file looks. A line of a key file
that is no key is counted in an item of its own.

At most 500 accounts, members and keys become items in one sweep. Where there
are more, your own sweep says in a note how many were not listed; the root
checks count that as something left unchecked, so the sweep is incomplete. The
same holds when the root checks find more than 200 accounts with a home under
`/home`: the keys of the rest are not looked at, and the sweep is incomplete.

After the first sweep that looked at these, a new or changed one is a high
finding at the next ("a key that may log in as you"), not only a line in
`--diff`; allow the ones you know. The first sweep that sees them has nothing
to compare with and only lists them. For what the root checks report (root's
keys, the accounts, another account's key count), the daily root collector
keeps its own record beside its results, where only root writes, and says
itself which are new, for two days from when it first saw them: what your
sweep remembers is a file of yours, and a program running as you could write a
label into it ahead of time. The collector's very first run has no record to
compare with and says so by sending no list; for that one run your sweep's own
memory stands in. A machine that runs the root checks only with `sweep --root`
never has that record: there your sweep's own memory stands in every time.

### Guardian's own units

The daily sweep is a user unit, so a file in your home can replace it or
change any line of it: any drop-in in
`~/.config/systemd/user/omarchy-guardian-sweep.service.d/` (one that sets
`HOME=`, `XDG_STATE_HOME=` or `ExecStart=`, say), a unit of the same name
earlier on systemd's search path, a mask, or the same in any other directory
of that path (`systemd-analyze --user unit-paths`): `user.control` and
`user.attached` under `~/.config/systemd`, `~/.local/share/systemd/user`,
`/run/user/<uid>/systemd`, `/etc/systemd/user`, `/etc/xdg/systemd/user`,
`/usr/share/systemd/user` and `/usr/local/share/systemd/user` (both come
before `/usr/lib/systemd/user`), Flatpak's exported data directories, the
runtime, transient and generator directories under `/run`, and for the root
checks' units the system's unit directories. Any of these (also a drop-in for
every `omarchy-…` unit or for every service) is a high finding of its own that
cannot be allowed. The root checks report the ones in your home too, so the
finding does not rest on a sweep the override may have redirected; one root
cannot hash (too large to read, closed to your own account, or not a regular
file) is reported by its path alone.

The bar looks for the same files every time it is asked, except drop-ins
beside the package's own units in `/usr/lib/systemd`: only the sweep can tell
one put there by hand from one a repository package ships. It shows the sweep
as partly on, and lists what the root checks reported.

## What runs now

The sweep looks at what runs **now**, listing only what does not add up, so a
clean system shows nothing here.

As a user only your own processes can be looked at; the root checks see all of
them. Your own sweep cannot name another account's program: a kernel-thread
look-alike, a tracer or a listener of another account is the root checks' to
report, and a note says how many listening sockets and processes were left to
them.

### Programs with no file, or from a temporary directory

A running program with no file on disk (deleted, or only in memory), or
running from a temporary or cache directory, is listed.

A program an update replaced while it runs is fine, but only at a path a
repository package owns. Anywhere else the file now at that path says nothing
about what runs (whoever deleted the program may have put it there): the
process is reported as running a program that is no longer on disk, the file
there is not hashed in its place, and what it preloads, whether it reads the
keyboard and whether it listens is checked as for any other. A file that is
merely called `x (deleted)` is told from a deleted one. In a user namespace of
its own a deleted program can carry any name, a packaged one included: what
that one preloads, and whether it reads the keyboard or listens on the
network, is checked as for a program no package installed.

A script an interpreter runs from a temporary or cache directory, and a
program the dynamic loader was handed from one, are listed too. A script given
by a relative name is looked for where the process runs now. An AppImage's own
start script is noted, not flagged. Where an option may or may not take a
value, both the argument after it and the next are looked at, so a data file
in a temporary directory passed to a script can be flagged in its place. Code
given on the command line or on standard input (`python -c`, a `bash -c`
command string) has no file to look at, and Java classes named by a class path
are not followed. Where a subcommand stands before the script (`deno run
x.ts`, `bun run x.ts`), the script is not found.

### Preloaded libraries

A library no repository package installed, loaded into a running program
(`LD_PRELOAD`, `LD_AUDIT`), is listed, and so is a program told to look for
its libraries in a temporary directory or in one relative to where it runs
(`LD_LIBRARY_PATH`; the empty entry launchers leave behind is ignored). A
preload given by a bare name, found through the library search path, is
flagged on the program. Steam's overlay library is noted, not flagged. This is
what the process was started with: one that rewrites its own environment
afterwards is not caught by it.

### Packaged files compared with their package

A packaged file that is no longer what its package installed is listed. A
running program, a preloaded library and a loaded kernel module are trusted
for their content, not for sitting at a packaged path: each is compared with
the digest pacman recorded, and one that differs is a modified package file
and is checked like a program no package installed.

The same comparison runs over `/usr/bin`, the libraries at the top of
`/usr/lib`, `/usr/lib/security`, the programs at the top of `/usr/lib/systemd`
and the running kernel's modules directory, where a changed file runs sooner
or later without being in any auto-run location; a file no package owns there
is listed as unknown (depmod's indexes and DKMS's modules are not). What this
finds in `/usr/bin` is listed under "The system's own programs".

Each file is compared once per sweep; up to 2 GiB are read in all for what
runs, and 8 GiB more for the directories. Past that your own sweep says in a
note that not every file was compared, and the root checks count it as
unchecked, so the sweep is incomplete. A single file over 512 MiB is not
hashed.

This pass reads a few gigabytes on every sweep, on several threads, and is
most of a sweep's time before any AI review; the units allow for a sweep that
takes minutes.

One change is told apart: a packaged script whose first line alone was
rewritten to name the same interpreter another way (Omarchy turns
`powerprofilesctl`'s `#!/usr/bin/env python3` into `#!/bin/python3` on every
install). The package's content is not on disk, only its digest, so the file
is hashed again with each line the package could have shipped for that
interpreter (`#!/usr/bin/env NAME`, `#!/usr/bin/NAME`, `#!/bin/NAME`; for
Python also `python`, `python3` and `python3.N`) in place of its first; when
one gives the recorded digest, everything after the first line is the
package's, byte for byte. The new first line must name a program in `/usr/bin`
that a repository package installed, with no arguments, and its set-id and
write bits must be what the package set. Only a script of up to 2 MiB is
tried. Such a file is listed as `edited` with a note and no alert, and is read
no more than any other packaged file. Any other difference is `modified`.

### Listeners

A program that listens on the network (TCP, not loopback) is listed, by every
process that shares the socket.

**How the item is named.** The item is named by the program and the port, and
for an interpreter with no script on disk by what it was told to run too, so
allowing one does not allow another script or port; a port the kernel picked
reads `listens`. For `python3 -m module` the item is the file Python runs for
that module (`/usr/lib/python3.14/http/server.py:tcp-8000`), looked for as
Python does, first where the process was started and then in the interpreter's
own library, so the allow is bound to that file's content: a module of the
same name beside where the command was typed is another item, a high finding
where it takes the place of the interpreter's own, and one more when it runs
from a temporary or cache directory. Where the file cannot be told for
certain, the name carries the module and a mark of the directory the process
was started in (`/usr/bin/python3:tcp-8000:other:cwd-…`).

**What vouches for a listener.** Only a service the process is itself in
vouches for it: a packaged unit's own control group for the system's services,
and for your own services a packaged user unit that names the program; an app
or terminal scope of your session vouches for nothing. The unit of a job
runner (cron, `atd`) vouches only for the program it names itself, not for the
jobs users hand it. A packaged program a packaged service runs, or a desktop
program known to listen (a browser, Syncthing, KDE Connect, Docker), is listed
with the trusted items.

**What is flagged.** Any other packaged program that listens is shown and
flagged low, so a new listener shows in `--diff` and in the daily
notification; so is an interpreter, the loader, `awk` or `openssl`, whatever
its script (`busybox` and `toybox` count as relays, below). A program no
repository package vouches for (an interpreter counts as that, whatever runs
it) that waits on a UDP port somebody chose, on an address other than
loopback, is listed the same way (not the common ports: DHCP, NTP, SSDP, mDNS,
LLMNR). As root, a listening socket that no process holds is a high finding,
unless a kernel module that serves files (NFS, SMB, iSCSI) is loaded.

### Remote shells and relays

A shell or interpreter whose input or output is a network connection, and a
shell that holds one among its open files (`bash -i >& /dev/tcp/…`, a socket
duplicated onto standard input in Python, `nc -e`), is a remote shell, flagged
high with the address it is connected to, or medium when that is this machine
itself. Pipes and local sockets, which terminals, IDEs and language servers
put there, are not network connections and say nothing. A packaged service
started per connection is not reported, unless its program is a shell.

Also listed: a tool that runs or forwards what it is told over the network
(`nc`, `ncat`, `socat`, `systemd-socket-activate`, `dropbear`, `telnetd`,
`chisel`, `ngrok`, `cloudflared` and the like) that listens or is connected to
another machine; an `ssh` that forwards ports (`-R`, `-D`, `-w`) started from
no terminal; and an `sshd` started with a configuration outside `/etc/ssh`, a
setting or a port of its own.

### Keyboard, camera and packet sockets

A program no repository package installed that reads the keyboard devices or
uses a camera is listed; and any program that holds a raw packet socket (what
a sniffer reads the network through), other than the packaged programs that
run or capture the network (NetworkManager, `iwd`, `dhcpcd`, `wpa_supplicant`,
`tcpdump`, Wireshark and the like). As root, a packet socket that no process
holds is reported too.

An interface in promiscuous mode is noted, unless it is part of a bridge or a
capture tool is running. Your own sweep leaves this to the root checks
whenever there are processes it cannot read.

### Kernel modules

A loaded kernel module no package installed is listed (one built by DKMS is
noted, not flagged), and so is one the kernel marks out-of-tree or unsigned
under an in-tree module's name or from a package not known to ship such
modules, and the kernel's taint flag. After a kernel update the running
kernel's modules are no longer a package's: until the next boot they are not
checked, and a note says so.

A taint only a module sets, with no loaded module that carries it, is a hidden
module. It is noted instead only where a module that would have set that very
taint is installed for the running kernel outside its own tree, is there as a
file and is not loaded now: out-of-tree and unsigned for any such module,
proprietary only for one with such a licence (NVIDIA's, ZFS), never a forced
load or a live patch.

### What hides

A process that answers under its number and is missing from the list of
processes is listed. The numbers the control groups name are tried, and every
number a process may have, up to the kernel's limit (numbers start over when
it is reached, so the last one handed out says little); were there ever more
than can be tried, the newest are and the sweep says so, as it does of a share
of the numbers its search did not get through.

So is a program named like a kernel thread (`[kworker/0:1]`); and, as root, a
process root cannot read. Root also says when it cannot list the pinned eBPF
objects.

### Debuggers and eBPF

A process attached to another the way a debugger is: high when the other holds
secrets (a shell, `ssh`, `sudo`, a key agent, a keyring, a browser, a password
manager), else medium. Where the other holds no secrets, a program started
under its tracer and a packaged debugger at work (`gdb`, `lldb`, `strace`,
`perf`) or an editor's debug adapter are not reported. Anything attached to a
program that holds secrets is reported whatever it is (`strace` around `ssh`
is how passwords are logged), except a shell a debugger started itself.

eBPF objects pinned in `/sys/fs/bpf` that are not systemd's or the traffic
tools' own are listed (as root only).

### Set-id files and capabilities

Setuid and setgid files, and files with capabilities, under `/usr`, `/opt`,
`/etc`, `/var`, `/srv`, `/root` and `/home` that no repository package vouches
for are listed (an AUR package's set-id file is listed too); a setuid copy of
a packaged program counts as unknown.

Pacman does not record capabilities, so any capability on a packaged file
other than exactly those its package is known to set is reported: high for all
of them (`=ep`) and for those that amount to root (`cap_setuid`,
`cap_dac_read_search`, `cap_sys_admin`, `cap_net_admin`, `cap_bpf` and the
like, or one with no name), medium for the rest.

The search for setuid and setgid files leaves out what holds other systems'
files: container, machine and Flatpak stores under `/var/lib`, `/var/cache`,
and snapshot directories (`.snapshots`). The search for files with
capabilities (`getcap -r`) leaves nothing out. Other mounted filesystems
(`/mnt`, `/media`, `/run/media`) are not looked through at all.

## How the machine was started

The command line of the running kernel (`/proc/cmdline`) is compared with the
boot configuration (Limine's, `/etc/kernel/cmdline`, and GRUB's and
systemd-boot's where they are used): a parameter that replaces init or the
unit to start, opens a shell (`init=`, `rdinit=`, `systemd.unit=`, `rd.break`
and the like), or turns a defence off (`module.sig_enforce=0`,
`lockdown=none`, `selinux=0`, `apparmor=0`, `audit=0`, `mitigations=off` and
the like) and that the configuration does not hold was typed at the boot menu
or put there by something that is not reviewed, and is a high finding.

Every `vmlinuz` under `/boot` (the first 32; more is said) is compared by
SHA-256 with the ones the installed kernel packages ship in
`/usr/lib/modules`. One that matches none is a high finding where it is an
image the machine starts by default or runs now: it goes by an installed
kernel package's name (`vmlinuz-linux`), or its header says it is the running
release. Any other is listed with a note and no alert: Limine with snapper
keeps older kernels for its snapshot entries, and no installed package can
vouch for those. `/boot` is usually root's alone, so this is the root checks'
to do, and your own sweep says so in a note.

A note also says whether Secure Boot is on; that it is off is said once, and
after that only with `--all`, until it changes. The EFI programs (the boot
loader itself) and what is inside the initramfs image are not looked at.

## How each item is judged

Each item is judged against pacman's own records (no network, no hash
lookups). Those records live in `/var/lib/pacman/local`, which root can
rewrite, so the sweep assumes them intact: an attacker who already has root
can make a changed file look packaged. A copy only counts as one when it has
the same name as the packaged file (and never of documentation, examples or
tests, of a package's configuration file, or of a file from a package no
repository vouches for), and a link only takes the trust of the unit it
enables under that unit's own name (or an instance of its template, or a name
it declares with `Alias=`), never for the units that open a root shell
(`debug-shell`, `emergency`, `rescue`):

| Tier | Meaning | Shown |
| --- | --- | --- |
| package | Exactly what a repository package installed | with `--all` |
| inert | A masked unit (link to `/dev/null`, or an empty file) or another empty file that no package owns; not when it masks a defence (Guardian's own sweep included) or a pacman hook a package ships. Also `/etc/locale.conf` or `~/.config/locale.conf` when it sets the locale and nothing else | with `--all` |
| copy | Identical to a file a repository package ships (Omarchy's `etc-overrides`) | with `--all` |
| user-built | From a package of no configured repository (AUR), or from a package file nothing checked (`pacman -U`), whatever its name; or put there by a version manager (mise) | yes |
| edited | A package's configuration file, changed as configuration is meant to be; or a packaged script proven to differ from its package in the spelling of its interpreter line alone (see above) | yes |
| allowed | Allowed with `sweep allow` while unchanged | with `--all` |
| modified | A package's file that is no longer what the package shipped (content, link, set-id or write bits, or read access for everyone taken away) | yes, and a high finding |
| unknown | No package installed it | yes |

A link of the same name to a packaged file is trusted only where that is how
the thing is enabled (a unit in a systemd unit directory, a hook in pacman's,
a launcher in an autostart directory, a program of `/usr/bin` or `/usr/lib` in
`~/.local/bin` or `~/.cargo/bin`) and the link names its target in full under
`/usr`, `/etc` or `/opt`, never to documentation or an example.

A package counts as a repository's when a repository carries its name and
pacman checked it on the way in: by its signature, or by the checksum the sync
database gave for it (`%VALIDATION%` in the local database says which). A
package file without a signature, installed by hand with `pacman -U`, has
neither (`none`), so its files are `user-built` and reviewed even when it
takes the name of a repository package, and they never vouch for a copy
elsewhere; a note names such packages. The version is not compared with the
sync database: a file can take any version, and a repository package that
waits for an update would read as built by the user.

Guardian itself is installed with `pacman -U` and is not named in that note:
the files its package ships, unchanged and not set-id, count as `package`;
anything else from a package of that name is `user-built`.

The defences whose mask is shown are firewalls (`ufw`, `firewalld`,
`nftables`, `iptables`, `ip6tables`, `opensnitchd`), `apparmor`, `auditd` and
`audit-rules`, `usbguard`, `fail2ban`, `sshguard`, `crowdsec`, the ClamAV,
AIDE and rkhunter units, the snapshot timers a rollback needs (`snapper-*`,
`grub-btrfsd`, `limine-snapper-sync`) and `btrfs-scrub`, `systemd-journald`
and Guardian's own. The mask of a pacman hook that a package ships (a file of
its name in `/etc/pacman.d/hooks`) is shown the same way. Masking
`systemd-resolved` or `systemd-coredump` is common and stays `inert`.

## What goes to the review

Everything shown that holds text goes through the local rules, and what is not
kept back below through the AI review (class `system`), with the review
memory, so a repeated sweep of an unchanged system makes no AI call.

### What is kept from the AI

Four kinds of file are read on this machine only. Each says so in a note on
its item (accounts, keys and certificate authorities do not: they are facts
with no text to send), and being kept makes no sweep incomplete.

- **A file whose path marks it as holding secrets** is never sent, whether or
  not something runs it and whatever its first line: anything under `.ssh`,
  `.aws`, `.gnupg`, `secrets` or `credentials`, `.env` files, `*.pem`,
  `*.key`, key files by their name (`id_ed25519`), `.netrc`, a name with
  `secret`, `credential` or `token` in it, and the like. That is asked of the
  path the content was read from and of the name a link gives it, not of the
  name an item is listed under. Such a file is still read by the local pattern
  rules and looked through for what it starts. So `~/.ssh/rc`, the script the
  SSH server runs at every login, is read like a shell start-up file here (a
  finding comes from what it holds, not from its being there), and so is a
  script under `~/.ssh` that a unit runs, or a `~/.env` a start-up file reads
  in. `/etc/ssh/sshrc` is under no such path and is reviewed like any script.

  Whoever writes a file picks its path, so such a path must not be a way past
  the review. Where something runs a file kept this way, the item raises a
  finding of its own, `kept-from-review` (medium): the AI did not read it,
  only the local rules did. Something runs it when:

  - it is a file of an auto-run location, or what a link there leads to;
  - a command names it, or a start-up file reads it in;
  - it is the SSH login script;
  - a live check found it running as a script.

  Two ordinary cases are passed over. A file a unit only reads as its
  `EnvironmentFile=` is a list of variables to systemd, which can run nothing
  from it. And the finding is skipped for a file whose every line only keeps
  a value in a variable, which is what the usual file of exported keys looks
  like. A line counts as that when all of this holds:

  - it is written as `NAME=value` (also after `export`, several on a line),
    fish's `set -gx NAME value`, Hyprland's `env = NAME,value` or `$name =
    value`, or is blank or a comment;
  - the name says secret (as for masking, below), or is a plainly inert
    setting: `LANG`, `LC_*`, `TZ`, `TERM`, `COLORTERM`, `USER`, `LOGNAME`,
    `HOSTNAME`, `EMAIL`, or a name ending in `_ID`, `_REGION`, `_PROFILE`,
    `_ACCOUNT`, `_USER`, `_USERNAME`, `_NAME`, `_ORG`, `_PROJECT`, `_ENV`,
    `_STAGE`, `_TENANT`, `_DATABASE`, `_DB`, `_PORT` or `_MODEL`;
  - the value is one opaque word: no `/`, no leading `~` or `.`, no `://`, no
    blank.

  Anything else raises the finding: any other variable, whatever it is called
  (most of what redirects a program is a variable set to a path, and no list
  of such names is ever complete); a value that is a path or an address; a
  `$`, a backtick or a backslash anywhere; `;`, `&`, `|`, a redirection or a
  bracket outside quotes; a quote left open; a command after an assignment;
  `source`, `eval`, `alias`, a function. `PATH`, `LD_*`, `PROMPT_COMMAND`,
  `BASH_ENV`, a proxy and their like raise it even where their name ends like
  an inert one. Which names are passed over is a judgement about noise, not a
  guarantee: a file the rule does not recognise costs one finding, answered
  with `sweep allow`. A secret nothing runs (a key or an `.env` that a process
  was merely handed) raises nothing either.

  The finding shows in the sweep, in `--diff` and in the daily notification
  when new or changed, and does not make the sweep incomplete. Read the file
  yourself; `sweep allow` records that you did, bound to its content. The
  local pattern rules read the whole file in every case.
- **SSH and git files in a home directory**: the files of the table above,
  what one of them is a link to (a `~/.gitconfig` kept in a dotfiles
  directory), and a file an SSH `Include` reads in. What is checked: an SSH
  line that runs a command or loads a library (`ProxyCommand`, `Match … exec`,
  `PKCS11Provider`, with blanks or `=`), a key with a `command=` or
  `environment=` option, and git keys that run a command. A credential helper
  is expected and passes, unless it is a shell line of its own or a program
  from a temporary directory; `url.*.insteadOf` rewrites are not judged.
- **Settings that hold tokens**: the package-manager settings, an editor's
  `settings.json`, fish's saved variables, accounts, keys, certificate
  authorities and `/etc/hosts`, each checked by the rules for its kind (see
  [More that decides what runs](#more-that-decides-what-runs)).
- **A file a live check names that nothing says is a script.** The live checks
  go by a process's arguments, and an argument may as well be a data file
  (`node --env-file …`). Its text is sent only where it starts with `#!` or
  has a script's name (`.sh`, `.py`, `.js` and the like), and is under no
  secret path; anything else is hashed, listed and read by the local rules.

A file an SSH `Include` names by its full path or with `~` is followed and
checked the same way, one with `*` in its last part to the files it matches. A
name relative to `~/.ssh` is not followed (`~/.ssh/config.d/` is read in any
case).

A linked file is treated as the file it stands for. Dotfile managers keep the
real file under another name (`~/.npmrc` as a link to `~/dotfiles/npmrc`):
what the link of a catalogued file leads to is read by the rules of the file
the link stands for (a linked `~/.ssh/rc` is the login script, a linked
`authorized_keys` a key file whose keys are listed as for any other) and,
where that file is kept from the AI, is kept from it as well. That holds
wherever the real file is kept: a `~/.gitconfig` that is a link to a file on
another mount is your home's configuration still. For the keys of another
account the root checks follow such a link only to a file that account could
read itself.

### What is sent

A program one of the files above runs is no such file: the script a
`ProxyCommand` or git's `sshCommand` names is followed and reviewed like any
other program, by the local rules and the AI, unless its own path marks it as
holding secrets. Such a script reads nothing in as configuration, whatever its
lines look like, and where it is itself a link, what the link leads to is the
script.

A settings file is kept as one only while every way the sweep reached it was
as configuration. One that a command names as well (a file one line includes
and another runs), or that a live check finds running, is a program, whatever
links to it or includes it: it is read by the local pattern rules, and sent
where the rules above allow it.

A file a start-up file reads in (`source ~/.config/shell/aliases`) is reviewed
and sent like the start-up file itself, unless its path marks it as holding
secrets.

Binaries no package vouches for are named to the AI by format and hash but
never run or uploaded.

### What is taken out of a file that is sent

Before a file is reviewed, two things are taken out of its text, for the local
rules and the AI alike:

- the value of an assignment whose name says secret: a part of it between
  `_` is `KEY`, `APIKEY`, `TOKEN`, `AUTHTOKEN`, `PAT`, `SECRET`, `PASSWORD`,
  `PASSWD`, `PASSPHRASE`, `PASS`, `PWD`, `PSK`, `AUTH` or `CREDENTIAL(S)` (as
  in `OPENAI_API_KEY`), or the name is one word that ends in `PASSWORD`,
  `PASSWD`, `SECRET`, `TOKEN` or `APIKEY` (`PGPASSWORD`). The value must be a
  literal of at least 8 plain characters (letters, digits and `_-./+=:@%,`),
  with or without quotes around it. The forms read are shell, `NAME=value`
  (with or without blanks around the `=`), unit `Environment=` and fish `set`;
- the password of an address (`https://user:password@…`), where it is plain
  characters, the user and host staying.

Start-up files are where exported keys live, and the sweep runs on a timer.
The rule is kept this narrow on purpose: what is taken out is hidden from the
local rules and the AI alike, so nothing that could be a command may ever be
taken out. A value with a blank, a `;`, `|`, `&`, `$`, a backtick or any other
punctuation in it stays to be read, quoted or not (`SECRET='p@ss w0rd!'` goes
with its file); so does anything after the assignment on the same line
(`PASS=1 curl … | sh` stays whole), and a value that says where something is
(a path, a URL).

A host or a program's name assigned to a secret-named variable
(`AUTH_HOST=updates.example.org`) is taken out like any other such value, and
so is hidden from both layers; the line that uses the variable is not.

What still goes with its file: a secret under another name, shorter than 8
characters, with a blank or punctuation in it, in YAML or JSON `key: value`
form, handed over as a command-line argument, or a key block (PEM) in a file
whose path gives no hint.

### After an upgrade

These show once after an upgrade from Guardian 0.8.1 or earlier:

- the scripts your SSH and git files run are sent for review, where their own
  path does not mark them as holding secrets; earlier versions kept them back;
- what your own unpackaged shell scripts start or source is listed, and sent
  for review like any other item, where it was not collected before;
- a `~/.ssh/rc` is read by the local rules for what it holds, and raises
  `kept-from-review` in place of `ssh-command`: allow it once you have read
  it. The same shows for any other script under a secret-looking path that
  something runs;
- an allowed file that a catalogued link leads to (`~/dotfiles/npmrc`) is
  shown again: it is now read by the rules of the file it stands for, and what
  those find is part of what an allow covers.

## Root checks

Some files only root can read (the sudoers file and drop-ins, polkit rules,
root's crontab, shell files and keys, the Limine config). Without root, the
sweep lists them and is **incomplete** (exit 2).

### What root reads and hands back

`sweep --root` asks for the sudo password and runs the installed, root-owned
Guardian as a collector that only reads: it never runs what it finds, makes no
AI call and writes nothing (but for moving the list of allowed items an older
Guardian left, once); it hands the items no package vouches for back to your
own sweep, which judges them with your settings. Only files of the auto-run
locations themselves (a sudoers drop-in, root's crontab) come back with their
content; anything root reached by following what they run or what a process
preloads comes back as a hash only.

Of the auto-run files, root's view only fills in what your own sweep could not
read (root's results may be a day old); of what runs now, it adds what it saw
of every account's processes.

### Paths a user can point root at

Where a user decides what is named (a crontab or other file that is not root's
alone, or any process, with the arguments and `LD_PRELOAD` it was given), root
looks only at what everyone may read anyway: anything else is not followed, or
is listed as not looked at, with no hash, no kind and no word on whether it
exists, so no user can point the collector at `/etc/shadow` or a key and learn
something about it. That holds through chains of links.

What the collector reads, in its own search for set-id files too, it reaches
by entering each directory as it opened it, so one swapped for a link while it
reads is not followed.

### The one thing told of a root-only file

One thing is told of a file not everyone may read: whether a packaged program
a process runs or preloads is still what its package installed. The path must
be one pacman's database holds, reached with no link on the way through
directories that are root's alone, and the answer is that one bit, never the
hash; what the package installed there is public anyway, and a package's
configuration file is never reported this way. Where such a path lies in a
directory not everyone may enter and holds no regular file, nothing is said
either, since "missing" would be a second thing told. So what a user can learn
there by naming a path is that one bit, "a packaged file differs from its
package", and a packaged file that is gone or is something else is left to the
look through the system's own directories, which no user steers. Without it, a
changed program made unreadable (`chmod o-r`) would pass for the packaged one.
A packaged file that lost the read access its package gives everyone is
`modified` in itself, for root and for your own sweep.

### Other accounts

Crontabs and `at` jobs of other accounts are left out of the results (a note
says how many): only root's, and those of the accounts in the group allowed to
read them (or, for `sweep --root`, yours) come back. An `at` job
(`/var/spool/atd`, `/var/spool/at`, `/var/spool/cron/atjobs`) starts with the
whole environment of whoever queued it, so it comes back as a hash only.

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
back is what a home's key file gives.

Of every other account with a home under `/home` only the number of keys comes
back, with a hash of the list so that a change shows: whose keys they are is
that account's to see, like its crontab (a key file of theirs too large to
read is said in that same line, and no more of it). Root's own keys come back
one by one. Where there are more items than the results hold, root's own and
the system's are kept first and what the accounts keep under `/home` after
them, so an account that fills its home cannot push root's keys out.

### What is read of `/etc/shadow`

`/etc/shadow` is read for one thing, by its fixed name: whether a system
account that has a login shell also has a password that works, yes or no. No
hash leaves the collector. Old password hashes (`/etc/security/opasswd`) are
never read.

## On a schedule

### The two timers

`protect` turns on two timers the package ships:

- a user timer (`omarchy-guardian-sweep.timer`), ten minutes after login (plus
  a random delay of up to half an hour) and then daily, running `sweep
  --scheduled`: anything new or changed that no package vouches for raises a
  notification ("Guardian found …") that opens the saved report, and the bar
  knight needs attention until you dismiss it, or for a day. Once the timer
  has run, new is measured against what its own sweeps have told about: a
  sweep run by hand (by you, or by a program that hopes to have its files
  taken as seen) does not count, so you may be notified of something you
  already looked at. A finding that appears on a file that did not change
  counts as a change; one that goes away does not. The first scheduled sweep
  has nothing to compare with: it notifies only when it found something with
  an alert or could not finish;
- a system timer (`omarchy-guardian-sweep-collect.timer`) for the root checks,
  but only after `protect` asks you and you agree.

`protect --off` turns both timers off and keeps your answer.

The scheduled sweep ends by asking whether a newer release of Guardian is out
(see [Hearing of a new release](install.md#hearing-of-a-new-release)); a sweep
run by hand does not.

The user unit gives up what the sweep and the AI reviewer it starts do not
need (gaining privileges, making set-id files, real-time priority, another
system-call interface). It cannot be given a read-only system the way the
collector is: in a user unit that puts the sweep into a user namespace of its
own, where every file of root's reads as nobody's, and the sweep could no
longer tell root's files (the list of allowed items, the root checks' results)
from anyone's.

### Consent

The answer is kept in the system file as `[sweep] root = "allowed"` (or
`"declined"`) with the group allowed to read the results; a user file cannot
set it, and `protect --yes` never answers it for you.

Without root checks (declined, or not answered yet) every sweep is incomplete
and says what it could not check, and the bar shows the sweep as not fully on.

### The collector's sandbox

The collector runs sandboxed:

- a read-only system;
- no way to open a network connection;
- no devices beyond the standard ones;
- of root's privileges only those to read files, look at other users'
  processes and hand its results to your group;
- only the system calls of an ordinary service, without mounting, modules, raw
  I/O, the clock or tracing;
- no keys of root's session, no message queues of the host's, and what it
  writes is closed to others;
- it is stopped after half an hour.

The sandbox limits what a bug in the collector could change; it does not
contain it: a process that is root and may read every file and every other
process's memory (`CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`) has the secrets of
the whole machine within reach if it is taken over.

### The results file

The collector writes only these (and, once, the list of allowed items an older
Guardian left there):

| File | Owner and mode | Used |
| --- | --- | --- |
| `/var/lib/omarchy-guardian/sweep/root.json` | root-owned, mode 0640, your group | by your sweep, only while it is root's alone and less than 36 hours old |
| `/var/lib/omarchy-guardian/sweep/trust-seen.json` | root's alone | by the collector: its record of the accounts and keys it has seen |

Results written by an older Guardian are still read, but count for less: what
your own sweep leaves to the root checks stays marked as not covered, with a
note, until the collector has run again. Results of a version this Guardian
does not know are not read at all, and the sweep says to reinstall.

The results file makes the root-only items it lists (a sudoers drop-in no
package installed, say) readable by your group, so it is only used when your
primary group is yours alone; if it is shared with other accounts, root checks
run only with `sweep --root`.

### When the sweep itself breaks

A sweep that speaks only when it finds something goes quiet when it breaks. So
every scheduled sweep records when it ran and how it ended (a sweep you run by
hand does not: it says nothing about whether the timer works). A scheduled
sweep that could not run or could not finish (the AI review unavailable,
something it could not check) raises a notification when that starts or its
kind changes, and the bar keeps saying so until a scheduled sweep finishes.

The bar also needs attention when the sweep is on and:

- no scheduled sweep has run for three days, or none has run yet;
- one started more than two hours ago and never ended (its unit stops it after
  an hour);
- root checks are on and their daily results are missing, older than 36 hours
  or not root's alone.

The first and the last count an hour after boot or login at the earliest, so
the timers get their turn first; after a long suspend they can show for the
half hour the timers take to catch up. The record is a file of yours: it
catches a sweep that broke, not a program running as you that sets out to fake
it.

## Working through what it finds

A sweep flags what it cannot vouch for, and some of that will be yours on
purpose: a wrapper in `~/.local/bin`, a keybinding that starts your own tool,
an alias. Look at each one, then either fix it or tell Guardian you know it:

```sh
omarchy-guardian sweep                                 # what is flagged, and why
omarchy-guardian sweep --root                          # also what only root can read, now
omarchy-guardian sweep --diff                          # only what changed since the last sweep
omarchy-guardian sweep --json                          # one JSON document
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
the list with your agent without waiting for the daily sweep. It does not go
with `--json`.

`--diff` compares with the last sweep. An item that could not be read then and
can be now (the root checks arrived) is not a change by itself, unless it now
raises an alert; it is judged like any other in the full sweep.

Use the path exactly as the sweep prints it, with `~/` for your home (quoted,
so the shell leaves the `~` alone).

Run `sweep`, `sweep allow` and `sweep forget` as yourself, without sudo: the
last two ask for the password themselves. Run as root they stop with that
advice, since an item in a home is allowed for the user who asks; `sweep` run
as root stops too and says to use `sweep --root`.

### What an allow covers

- An allow covers the file's current content and what the live checks saw
  about it. If the file changes, or the same program starts reading the
  keyboard, listening on the network or running with extra rights, it is shown
  again and the daily sweep notifies about it.
- Allowing a file stops its alerts, including the AI's, so a sweep with only
  allowed items comes back clear. It does not change the file or make what it
  runs safe: allow what you have read and meant to have.
- `sweep allow` looks at the item again and allows it as it is at that moment.
  It prints the fingerprint it allows, and where that is not what the last
  sweep showed you (the file changed since, or no sweep has listed it), it
  says so and asks on the terminal first; without a terminal it allows
  nothing. What the last sweep showed is read from the sweep's own record, a
  file of yours: the question catches a file that changed between your reading
  the sweep and allowing it, and nothing more. A program running as you can
  rewrite that record to match, so the fingerprint printed is what to go by.

### What cannot be allowed

- What cannot be read at all (a program that exists only in memory, a deleted
  file) cannot be allowed; it stays listed while it runs. Nor can what
  overrides Guardian's own units, or an item whose commands were not all
  followed.
- Items only root can read (in `/root`, `/etc/sudoers.d`) can be allowed once
  the daily root checks have run (root checks allowed in `protect`); `sweep
  allow` uses their latest results.

### Where the list is kept

Every allow is kept in one list only root writes and everyone reads
(`/var/lib/omarchy-guardian/allowed.json`, mode 0644 in a root-owned 0755
directory), so `sweep allow` and `sweep forget` ask for the sudo password, for
items in your home too.

A program running as you can write any file of yours: were the list one of
them, it could drop an autostart entry and allow it in the same breath.

An item in a home is kept under the user id it was allowed for, so what you
allow in your home says nothing about another account's file of the same name;
`forget --all` drops the system's items and yours, not other accounts'.

### Lists from older versions

Guardian up to 0.7.18 kept the list beside root's results, in
`/var/lib/omarchy-guardian/sweep/`, which only the configured group may enter:
a second user's allow was written and never read. The root half moves the old
list on its next run (an allow, a forget, the daily root check or `sweep
--root`); until then a sweep that can reach the old one reads it.

Earlier versions of Guardian kept the allows for your home in a file of your
own (`~/.local/state/omarchy-guardian/sweep/allowed.json`). It no longer
counts, and a sweep says how many entries it holds. `sweep allow --migrate`
lists them and, after you say yes and give the sudo password, moves the ones
whose files are still exactly what you allowed; the rest (changed, gone, or
not allowable) are named and dropped with the old list. It needs a terminal,
and a no leaves the old list as it is. Read the list before you say yes:
anything running as you could have added to it.

### Records that are your own

What the scheduled sweeps have already told you about (`told.json`) is your
own file too, since the sweep that writes it runs as you: a program already
running as you can add to it and so quiet a notification for something new in
your home or the system. The alert itself, and the bar, still show it.

## Rule ids

The sweep's own findings carry these rule ids, as the report and `--json`
show them. The rules that read text, which the sweep applies to what it
reviews as well, are listed under [Local rules](local-rules.md#rule-ids).

| Rule id | Severity | What it reports |
| --- | --- | --- |
| `modified-package-file` | high | A file a package installed has been changed since; it is not what the package shipped. |
| `hidden-program` | high | A running program has no file on disk: it was deleted, or lives only in memory. |
| `preloaded-library` | high | A library no package installed is preloaded into a running program (`LD_PRELOAD`). |
| `unknown-kernel-module` | high | A loaded kernel module was not installed by a package. |
| `unknown-privileged-file` | high | A file no package vouches for runs with extra rights (setuid, setgid or capabilities). |
| `guardian-override` | high | A unit file or drop-in changes what Guardian's own sweep runs; allowing the file does not quiet this. |
| `path-hijack` | high | A program or directory a user can write comes ahead of the system's own on `PATH` and takes over a command's name. |
| `new-trust` | high | Something that was not there at the last sweep may now log in, administer or vouch here: an account, a member of an administrator group, an SSH key or a certificate authority. |
| `privileged-account` | high | An account has rights no ordinary system gives it: a second account with user id 0, or a system account someone can log in to. |
| `boot-tampering` | high | The running kernel was started with a parameter that turns off a defence or replaces init and that the reviewed boot configuration does not hold, or a kernel image in `/boot` is not the one its package ships. |
| `rootkit-sign` | high | The kernel's own lists disagree (a process, module or socket that exists is not listed), or a program wears a kernel thread's name: what something hiding itself looks like. |
| `traced-secrets` | high | A process is attached, the way a debugger is, to a program that holds secrets (a shell, SSH, sudo, a key agent, a browser, a password manager). |
| `ssh-command` | medium | An SSH file runs a command or loads a library (a `ProxyCommand`, a `Match exec`, a provider library), or a key carries a `command=` or `environment=` option. |
| `running-from-temp` | medium | A program runs from a temporary or cache directory, where downloads land. |
| `keyboard-reader` | medium | A program no package installed reads the keyboard device directly. |
| `risky-configuration` | medium | A configuration file redirects where programs, packages or web pages come from, or loads code into a program at every start. |
| `unexpected-capability` | medium | A packaged program holds file capabilities its package does not set (pacman does not record them, so the file itself is unchanged). |
| `network-relay` | medium | A tool that runs or forwards what it is told over the network (netcat, socat, a tunnel) listens or is connected. |
| `traced-process` | medium | Another process is attached to this one the way a debugger is, and can read and change its memory. |
| `kernel-tap` | medium | Something no package explains taps the kernel's network or tracing path: a raw packet socket, or a pinned eBPF object. |
| `kept-from-review` | medium | Something runs this file, or a shell reads it in, and it holds more than opaque values kept in secret-named or plainly inert variables; its path marks it as holding secrets, so the AI review did not read it: only the local rules did. Read it yourself; `sweep allow` records that you did. |
| `network-listener` | low | A program listens on the network that nothing installed accounts for: an interpreter (Python, a shell, Node), or a packaged program no packaged service runs. |

`git-config-command` and `remote-shell` are reported by the sweep as well as
by source reviews: the first for a git key in a home that runs a command, the
second for a running shell or interpreter on a network connection.
