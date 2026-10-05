# Settings, profiles and status

How Guardian is configured and how it shows its state: the settings app, what
the bar widget and `omarchy-guardian status` count as on, the source classes
and profiles, the two settings files and who may set what, the settings
commands, and the table of decisions and exit codes.

## Contents

- [Settings app](#settings-app)
- [The bar and `status`](#the-bar-and-status)
- [Source classes](#source-classes)
- [Profiles](#profiles)
- [Settings files](#settings-files)
- [The reviewer under the pacman hook](#the-reviewer-under-the-pacman-hook)
- [Settings commands](#settings-commands)
- [Decisions and exit codes](#decisions-and-exit-codes)
- [Note for upgrades from early versions](#note-for-upgrades-from-early-versions)

## Settings app

The settings app (`omarchy-guardian tui`) turns every gate on with *Protect
everything*, picks the protection level and the model, and tests the reviewer
with a malicious and a harmless sample.

`omarchy-guardian tui` edits every setting without touching TOML by hand. It
installs a launcher entry ("Omarchy Guardian") that opens as a floating
window, and can add itself to the Omarchy menu under Setup › Guardian.

It opens in **simple mode**, where the Guardian (the app's mascot) tells you
how you are protected. Here you choose a protection level, which sets the
profile for your own sources and for pacman alike:

| Level    | Profile      | What it does                                              |
| -------- | ------------ | --------------------------------------------------------- |
| Balanced | `standard`   | AI review for AUR builds, themes and third-party packages |
| Maximum  | `strict`     | AI review for everything; any finding blocks              |
| Private  | `local-only` | no AI: nothing leaves the machine; you confirm installs   |

You can also pick the model used for both (Claude Code models are listed and
suggested when `claude` is installed, otherwise OpenCode's), turn on every
install gate at once (*Protect everything*), test the reviewer (`t`), or reset
to the defaults.

Press `e` for **expert mode** (or start there with `tui --expert`), which has
every setting:

| Tab | What it changes |
| --- | --- |
| Profiles | the profile for your own sources (user file) and for the pacman gate (system file) |
| Sources | every knob of every source class; pacman-enforced classes in the system file, the rest in the user file |
| AI | model, input size and call limits for your sources and for the pacman gate, review-memory limits, official repositories |
| Integrations | turn the pacman hook, the yay AUR gate, the theme & plugin gate, the theme & plugin commands on PATH, the Omarchy menu entry, the bar widgets and the system sweep on or off |
| Maintenance | show and check the effective settings, edit either file in `$EDITOR`, see or forget the review memory, test the reviewer, run the guided setup |

Unset values show what they inherit and from where. Keys: `↑↓` move,
`Tab`/`1`–`5` switch tabs, `Enter` edit, `Space` cycle a choice, `x` reset to
inherit, `u` undo, `s` save, `e` back to simple mode, `q` quit. Every edit is
checked with the same parser that reads the files, so the app cannot save a
file Guardian would reject. The user file is written directly (a hand-written
one is kept as `config.toml.bak`, since comments are not preserved). The
system file is saved only after showing a diff, with `sudo`, like `setup`
does. A file that does not parse cannot be edited in the app; fix it with
Maintenance › Edit. Before Guardian first edits `~/.bashrc`, the Omarchy menu
file or the Waybar config and style, it keeps the file as it was beside it, as
`<name>.guardian-bak`; later edits leave that copy alone. What you turn on or
off here is recorded as your choice, so it raises no "protection changed"
notification.

## The bar and `status`

The Guardian knight sits in the bar: calm when every gate is on, red-eyed when
something needs attention (a gate is off, a setting is broken, the daily sweep
stopped running or could not finish, or a block in the last day is unseen),
dim when protection is off.

A gate that cannot be there (the package's files are missing) counts as a
problem; a gate with nothing on this machine to guard does not: the AUR gate
without yay installed, and, without Omarchy (plain Arch), the theme and plugin
commands on PATH.

A gate counts as on only when it is in effect, not when a line that looks like
it is in a file: the Bash interceptor's exact line where Bash runs it and with
nothing after it that unsets or replaces its functions, the menu entries that
are in effect when the menu reads its file, yay building through Guardian's
root-owned shim with no alias or function in front of it that itself passes
another `--makepkg` and no other `yay` before it, and Guardian's theme and
plugin commands first on the session's PATH: its line in
`~/.config/hypr/hyprland.lua` where Hyprland runs it, after Omarchy's own
`envs.lua` has put Omarchy's commands first, and the PATH the session really
has. Which `yay` and which theme commands are found is read from the session's
own PATH (`systemctl --user show-environment`), the same for the bar and for a
`status` typed over SSH or in a shell that rearranged its PATH; where a
shell's own PATH differs, `status` says so beside the gate without calling it
a change. Anything less reads "partly on" with the reason.

The pacman hook counts as on by its link in `/etc/pacman.d/hooks`, not by the
hook file the package always ships. The sweep reads "partly on", naming the
file, when a unit or drop-in stands in for one of its own units (the same
files the sweep alerts on; see [Guardian's own
units](system-sweep.md#guardians-own-units)), and what the daily root checks
saw of that kind is a problem of its own. paru, pikaur, aura or trizen
installed without the gate is a problem too.

A class set weaker than its protection level (the AI review lowered or off,
findings that only warn, the no-AI level's question taken away) is a problem
until you set it back or accept it with `omarchy-guardian config acknowledge`;
accepted, it says "local checks only" or "findings only warn" beside the gate.

When a gate that was on goes off or partly off without you turning it off
through Guardian, a class becomes weaker, the pacman gate's root-owned
reviewer goes away, a settings file stops parsing, or a system-wide settings
file of the reviewer's appears (`/etc/claude-code/managed-settings.json` and
its `.d` directory, `/etc/opencode/opencode.json`: they apply to every review,
whatever Guardian passes the reviewer), you get one notification ("Guardian
protection changed"), from the bar's own check or the daily sweep; what
dropped stays listed until it is back or `omarchy-guardian status --dismiss`.
That record is a file of your own, like the list of dismissed blocks: it
catches things breaking and crude tampering (a line removed from `~/.bashrc`),
not a program running as you that also rewrites the record. A dismissed-blocks
mark that names a report newer than any saved one is not believed.

In Waybar its tooltip lists the gates, problems and last block; left-click
opens the settings app and right-click the last report. In Omarchy's shell bar
it opens a panel with the same details and tiles for the report, turning
protection on or off, and the settings. `omarchy-guardian protect` adds it to
whichever bar you run.

## Source classes

Every review is tagged with the class of its source. Classes reviewed by the
pacman hook are *privileged*: Guardian's own settings for them can only be
loosened by the system file (but see below for what of the reviewer stays in
the invoking user's hands).

| Class | Source | Enforced by | Privileged |
| --- | --- | --- | --- |
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
`SigLevel = Optional` or `TrustAll`; check with `pacman-conf --repo=omarchy
SigLevel`.

## Profiles

A profile is a named preset for every knob (`ai`, `on_findings`,
`on_ai_suspicious`, `thinking`, `confirm`, `cache`, `diff`) of every class:

| Profile | `official` | other classes |
| --- | --- | --- |
| `standard` (default) | `ai = optional`, `thinking = low`, `on_findings = warn`, `on_ai_suspicious = block` | `ai = required`, `thinking = high`, `on_findings = block`, `on_ai_suspicious = block` |
| `strict` | `ai = required`, `thinking = medium`, `on_findings = block`, `on_ai_suspicious = block` | `ai = required`, `thinking = max`, `on_findings = block`, `on_ai_suspicious = block` |
| `local-only` | `ai = off`, `on_findings = warn` | `ai = off`, `on_findings = block`, plus `confirm = true` for user-level classes |

`cache` and `diff` are `on` for user-level classes (`diff` is `off` under
`strict`) and always `off` for the pacman classes, where setting them is a
config error.

`confirm` only applies with `ai = off`, on the user-level classes (the pacman
hook has no reliable terminal): after clean local checks it asks on `/dev/tty`
whether to proceed; no terminal or no explicit yes blocks the run.

## Settings files

Settings come from two files of the same format:

- system: `/etc/omarchy-guardian/config.toml`
- user: `$XDG_CONFIG_HOME/omarchy-guardian/config.toml`, default
  `~/.config/omarchy-guardian/config.toml`

For the privileged classes, a user-file value for a knob applies only when it
is at least as strict as the value from the profile and system file, and
`thinking`, `model`, `timeout_secs`, `[agent]`, `[agent.variants]` and
`official_repos` are never taken from the user file or a user profile at all
for those classes. For the user-level classes, the user file's values apply
directly, since those commands never reach the privileged pacman gate.

That file is yours, so any program running as you can write it. Two things
keep that from quietly switching a gate off:

- A user file that is there and does not parse is not skipped. While it is
  broken, `makepkg-gate`, `guard`, `scan`, `sandbox` and `sweep` refuse with
  exit 2 and name the file and line, as the pacman gate does for the system
  file. (Skipping it would review at `standard` whatever stricter profile it
  holds.) `config check`, `config show`, `tui` and `setup` still work, to fix
  it.
- A user-level class set weaker than its profile (`ai` lower, `on_findings` or
  `on_ai_suspicious` on `warn` where the profile blocks, `confirm = false`
  under `local-only` with the AI off) still applies, and the bar counts it as
  a problem. To keep it, run `omarchy-guardian config acknowledge`: it lists
  those settings, shows the change to the system file and installs it with
  `sudo`:

  ```toml
  [acknowledged]                        # system file only
  weaker = ["aur.ai=off"]               # class.knob=value, as accepted
  ```

  Only root can write that file, so a program running as you cannot accept its
  own change, and an accepted value does not cover a lower one later. `cache`,
  `diff`, the model and the thinking level are choices, not weakenings. A
  weaker value in the system file itself needs no acknowledgement. Choosing
  the `local-only` profile in the user file is a protection level, not a
  weakening: it turns the AI review off for your own sources and asks before
  each install.

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
`[agent.variants]` maps it, because variant names differ between providers. An
unmapped level uses the provider's default and is shown as, for example, `high
(provider default)` in `config show` and in reports. `setup` writes the
mapping for the level its test run passed with, in both files.

## The reviewer under the pacman hook

The pacman hook runs the review as the invoking user from an empty
environment, without a login shell, so shell rc files and exported variables
cannot affect it. For that review OpenCode is given empty, private
configuration and cache directories, so the user's own OpenCode settings (a
provider `baseURL`, plugins, a global `AGENTS.md`) do not shape it. Its
credentials still come from that user's OpenCode data directory, and the
Claude Code CLI uses that user's Claude login: the review is kept apart from
the account's configuration, not from the account. What remains in the
account's hands, and the system-wide settings neither CLI can be told to skip,
are listed under [How the reviewer is run](review.md#how-the-reviewer-is-run).

## Settings commands

- `omarchy-guardian setup` — interactive wizard that detects OpenCode and
  Claude Code (suggesting Claude Sonnet when `claude` is installed), lets you
  choose a profile, model(s) and thinking level, runs a two-sample test
  review, then writes the user file and (with confirmation) the root-owned
  system file.
- `omarchy-guardian config show [--class NAME]` — effective policy per class,
  each value tagged `profile`, `system` or `user`, plus any ignored user
  values and why.
- `omarchy-guardian config check` — validates both files and the system file's
  ownership; exit 0 valid, 2 invalid.
- `omarchy-guardian config path` — prints both file paths.
- `omarchy-guardian config acknowledge` — accepts, in the system file and with
  `sudo`, the user file's settings that are weaker than the profile.

`scan` and `guard` take `--class NAME` (default `source`; one of the
user-level classes `aur`, `theme`, `plugin`, `source`) to tag the review with
its source class. `--class system` is rejected: that class is the sweep's own,
and so are the pacman classes the hook's. `scan`, `guard` and `sandbox` take
`--profile NAME` (`standard`, `strict`, `local-only`) to override the profile
for that one run; it cannot affect a privileged class, because these commands
never review one. The makepkg gate reviews as `aur`; the Omarchy theme and
plugin handlers pass `--class theme` and `--class plugin`.

## Decisions and exit codes

| Decision | Exit | When |
| --- | --- | --- |
| `CLEAR` | 0 | nothing found, review complete |
| `WARNED` | 0 | only findings whose policy is `warn`, or the AI review was unavailable under `ai = optional` |
| `LIMITED REVIEW` | 0 | nothing reviewable (a scriptlet-free pacman transaction); `guard` and `sandbox`, which start nothing then, exit 2 |
| `HIGH RISK` / `REVIEW REQUIRED` | 1 | any finding whose policy is `block` |
| `INCOMPLETE` | 2 | any non-AI gap, or an invalid AI reply (malformed, missing nonce, tool use, `inconclusive`), in every profile |
| `AI REVIEW UNAVAILABLE` | 2 | the AI review was unavailable under `ai = required` |
| `NOT CONFIRMED` | 2 | `confirm = true` and the user did not approve; or the makepkg gate asked about prebuilt programs, or about a recipe whose sources it cannot follow, and got no yes (no terminal counts as no) |
| `PERMITTED` | 0 | one of the blocking decisions above, overruled by your permit for exactly this content (see [After a block](permits.md)) |

Before any of these, a user settings file that does not parse ends `scan`,
`guard`, `sandbox`, `makepkg-gate` and `sweep` with exit 2 and nothing
reviewed or run; a broken system file does the same to the pacman gate.

## Note for upgrades from early versions

Upgrading users on the default `standard` profile: official Arch/Omarchy
packages now `WARN` on local-rule findings and proceed without the AI review
when it is unavailable, where they used to block. To restore the old
behaviour, set in the system file:

```toml
[class.official]
ai = "required"
on_findings = "block"
```
