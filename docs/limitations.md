# Limitations

What Guardian does not do. A clear result is not a safety guarantee; this page
says what a clear result means, lists the limits that matter most and what is
not covered at all, and links to the place where each gate states what it does
not see.

## What a clear result means

A clean result only means the static checks, the configured AI provider and
the available OSV data did not identify a problem in the files reviewed.
Guardian can miss malicious behaviour and benign code can match a rule. It
does not inspect compiled package payloads, cannot prove an installed binary
was built from the reviewed source, and does not intercept direct downloads or
`curl | sh`. The sandbox is optional and limited to a 120 s run.

## The limits that matter most

The limits of each part are stated where the part is described. The ones that
matter most:

- **The reviewer can be talked to.** The reviewed text reaches the model, and
  can address it. The local rules, the nonce and the model's own report of
  being addressed catch what they catch; none proves a careful reading.
- **A program already running as you** can change what you own: the user
  settings file (a weaker setting is shown by the bar until root accepts it),
  the review memory, the records the sweep and the bar keep (what the last
  sweep showed, what the scheduled sweeps already told you about, when the
  last one ran), the session's PATH file, and Guardian's lines in
  `hyprland.lua` and `~/.bashrc`. It can also write journal entries that look
  like Guardian's own ([What Guardian
  decided](audit-trail.md#what-an-entry-proves-and-what-it-does-not)). The
  pacman gate, the list of allowed sweep items and the accepted weaker
  settings are root's and are not in its reach. The reviewer's login and, for
  your own sources, OpenCode's configuration are yours too.
- **Root is trusted.** The sweep judges files by pacman's own records, which
  root can rewrite, and the pacman gate reviews as the user who called `sudo`,
  with that user's reviewer login.
- **System sweep:** as a user only your own processes can be looked at, and
  without root checks every sweep is incomplete. The EFI programs and the
  inside of the initramfs image are not looked at; other mounted filesystems
  (`/mnt`, `/media`, `/run/media`) are not searched for setuid files; the
  running kernel's modules are not checked between a kernel update and the
  next boot; what a process does to its own environment after it started is
  not seen; and only shell scripts no package vouches for are looked through
  for what they start, three deep, not scripts of other interpreters, and
  inside a script only a program named by a path in the place of a command
  ([System sweep](system-sweep.md#where-following-stops)).
- **Packages:** only scriptlets, auto-run files and the text files those name
  are reviewed, not the rest of the payload; a removal is not reviewed; a unit
  you enable yourself later is not reviewed then; front ends that call libalpm
  directly are blocked, not reviewed.
- **AUR builds:** yay's download-and-verify call runs the reviewed recipe as
  you before the sources are reviewed; dependencies a build downloads itself
  are not reviewed; prebuilt programs are your decision, not a review; with
  the AI off, the upstream code is read only by the local rules' high checks.
- **Themes and plugins:** only installs and updates that reach Guardian's
  commands are reviewed. A session not started through uwsm and Hyprland (SSH
  and console logins) has the Bash interceptor only, and another shell there
  has nothing (see [Omarchy themes](themes-and-plugins.md#not-covered) for
  the callers that do not reach them).
- **Source leaves the machine** through the AI provider you configured, except
  under `local-only`, and except the files kept from the AI by name or kind
  (SSH and git files in a home, package-manager settings that hold registry
  tokens, an editor's `settings.json`, fish's saved variables, `/etc/hosts`,
  `at` jobs). A file whose path marks it as holding secrets is never sent,
  by any gate or by the sweep, whatever runs it; where something runs it
  and it holds more than settings of variables to plain values, the sweep
  says so in a finding (`kept-from-review`) and only the local rules have
  read it. A secret under a name Guardian does not recognise, with
  a blank or punctuation in it, in YAML or JSON form, as a command-line
  argument, or a key block in a file whose path gives no hint, still goes
  with its file ([System
  sweep](system-sweep.md#what-is-taken-out-of-a-file-that-is-sent)).
  Under `local-only` no source is sent to an AI, but lockfile package names
  and versions still go to the OSV API (`api.osv.dev`), and an AUR package's
  name (and the names in its PKGBUILD's `pkgname=` lines) to the AUR.
- **Releases:** a first install cannot check the release signature (there is
  no installed key yet), and someone who controls where you pull from can
  withhold a newer release, though not forge one; see [Verifying a
  release](install.md#verifying-a-release) and [what the upgrade check relies
  on](install.md#what-the-upgrade-check-relies-on).

## Not covered at all

- Programs you download and run yourself, and `curl | sh` pasted into a
  terminal. `omarchy-guardian guard` and `sandbox` cover a download you start
  by hand.
- Flatpak, npm, pip, mise and other language package managers.
- The binaries inside a package (only what runs at install or boot is
  reviewed).
- Dependencies a build downloads by itself (cargo crates, npm packages).
- A theme or plugin copied into place by hand, or installed by a caller that
  names Omarchy's command by its full path or resets `PATH`, or from a session
  not started through uwsm and Hyprland in a shell other than Bash: it does
  not pass a gate.
- With the AI review off for AUR builds, the upstream sources: they are read
  only by the local rules' high checks.

Each gate's page says what its gate does not see.

## Where each part states its limits

The full text of each limit is on the page of its part, not repeated here:

- [Pacman gate: what the gate does not
  see](pacman-gate.md#what-the-gate-does-not-see), the moment between the
  hook's exit and pacman opening the archive ([How archives are
  located](pacman-gate.md#how-archives-are-located)), links root made by hand
  in a directory only root can list ([Symbolic
  links](pacman-gate.md#symbolic-links)), what an upgrade passes over
  ([Upgrades](pacman-gate.md#upgrades)), paths a script builds at run time
  ([Files the reviewed files
  name](pacman-gate.md#files-the-reviewed-files-name)), and front ends that
  call libalpm directly ([How the hook
  runs](pacman-gate.md#how-the-hook-runs)).
- [AUR gate: what is not reviewed](aur-gate.md#what-is-not-reviewed), the call
  that only downloads and verifies, what the fetch can reach on your network,
  what a recipe can tell about being listed, and what stands between the
  listing and the build ([Step
  4](aur-gate.md#step-4-upstream-code)), and prebuilt programs ([Step
  5](aur-gate.md#step-5-prebuilt-programs)).
- [Themes and plugins: not covered](themes-and-plugins.md#not-covered), and
  what the bar's reading of `~/.bashrc` does not see ([The Bash
  interceptor](themes-and-plugins.md#the-bash-interceptor)).
- System sweep: what is and is not followed ([What it
  reads](system-sweep.md#what-it-reads)), what the live checks miss ([What
  runs now](system-sweep.md#what-runs-now)), the EFI programs and the
  initramfs ([How the machine was
  started](system-sweep.md#how-the-machine-was-started)), pacman's records
  taken as intact ([How each item is
  judged](system-sweep.md#how-each-item-is-judged)), secrets that still go
  with a file ([What goes to the
  review](system-sweep.md#what-goes-to-the-review)), what the root collector
  could reach if taken over, and records that are files of your own ([On a
  schedule](system-sweep.md#on-a-schedule), [Working through what it
  finds](system-sweep.md#working-through-what-it-finds)).
- Review: what the nonce shows and does not ([What is
  checked](review.md#what-is-checked)), what makes a review incomplete ([What
  is read](review.md#what-is-read-and-what-makes-a-review-incomplete)), what
  stays in the hands of anything running as you ([How the reviewer is
  run](review.md#how-the-reviewer-is-run)), a payload split over two chunks
  ([How the review scales](review.md#how-the-review-scales)), and what an
  upgrade review does not see and the review memory in your home ([Review
  memory](review.md#review-memory)).
- [Local rules](local-rules.md): they read text, not meaning.
- Audit trail: [what an entry proves, and what it does
  not](audit-trail.md#what-an-entry-proves-and-what-it-does-not).
- Permits: [what a permit is](permits.md#what-a-permit-is) and [what no permit
  covers](permits.md#what-no-permit-covers); the report handed to your AI
  agent ([The report](permits.md#the-report)).
- Settings: what a program running as you can change in the user file
  ([Settings files](settings.md#settings-files)), what of the reviewer stays
  with the invoking user ([The reviewer under the pacman
  hook](settings.md#the-reviewer-under-the-pacman-hook)), and what the bar's
  record catches ([The bar and `status`](settings.md#the-bar-and-status)).
- Releases: [Verifying a release](install.md#verifying-a-release) and [what
  the upgrade check relies on](install.md#what-the-upgrade-check-relies-on);
  the known limits are also listed in [SECURITY.md](../SECURITY.md).
- `sandbox` is a behaviour smoke test, not a dynamic malware detector
  ([Commands](commands.md)).
