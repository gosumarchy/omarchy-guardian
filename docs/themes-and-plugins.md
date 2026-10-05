# Themes and plugins

How Omarchy theme and plugin installs and updates are routed through Guardian:
its commands first on the session's PATH, the Bash interceptor and the
overrides in the Omarchy menu file. This page says what each of the three
catches, how a theme or plugin is staged and reviewed, and which callers reach
Omarchy without passing a gate.

## Omarchy themes

Theme installs and updates are routed through Guardian in three places.

### Commands on PATH

This is *Theme & plugin commands (PATH)* in the Integrations tab. The package
ships root-owned commands named `omarchy`, `omarchy-theme-install`,
`omarchy-theme-update`, `omarchy-plugin-add` and `omarchy-plugin-update` in
`/usr/lib/omarchy-guardian/bin`. Every caller that finds those commands by
name goes through Guardian once that directory comes first on PATH: scripts,
`bash -c`, zsh and fish, launchers, key bindings, the stock menu entries and
AI agents. Guardian's `omarchy` hands theme and plugin installs and updates to
Guardian and passes everything else straight to Omarchy's own `omarchy` by its
full path (which finds its commands in its own directory, not on PATH, so
wrapping the four commands alone would miss `omarchy theme install`). It looks
for that one first in the checkout that `omarchy dev link` named in the
root-owned `/etc/omarchy.conf`, then in `/usr/share/omarchy/bin`, then in
`/usr/bin`; never on PATH, where it would find itself or a planted file.

Getting that directory first takes two things, because Omarchy sets PATH
twice. uwsm reads `~/.config/uwsm/env.d/90-omarchy-guardian`, which `protect`
writes, after Omarchy's own session file. Then Omarchy's Hyprland defaults
(`/usr/share/omarchy/default/hypr/envs.lua`) rewrite PATH with Omarchy's
command directory in front for everything Hyprland starts, and its autostart
hands that PATH to the systemd user manager and to D-Bus; with the session
file alone, Omarchy's commands would be found first by every key binding,
launcher, the menu, the bar and zsh or fish. So `protect` also adds two lines
at the end of `~/.config/hypr/hyprland.lua` (a comment, and the line that loads
Guardian's file), the place Omarchy keeps for your own configuration, read
after its defaults and before Hyprland starts anything:

```lua
-- Omarchy Guardian: its theme and plugin commands first on PATH. Keep this after Omarchy's defaults.
pcall(dofile, "/usr/lib/omarchy-guardian/hyprland-path.lua")
```

The file it loads is root-owned and part of the package: it puts Guardian's
directory first and Omarchy's right behind it. The second line passes over a
file that is not there. Nothing under `/usr/share/omarchy` is edited, so an
Omarchy update changes none of it. `omarchy refresh hyprland` replaces
`hyprland.lua` and with it both lines; the bar then shows that and notifies,
and `protect` puts them back. A Hyprland configuration that is not Lua (no
`hyprland.lua`) gets no lines.

It applies from the next login and reads "partly on", with the reason, until
then. It also reads so when the line is commented out, inside a string, a
function or a block, after a `return` or `os.exit`, or followed by another line
that sets PATH; when the session file or the line is missing while the other is
there; when one of Guardian's commands or `hyprland-path.lua` is not root's
alone to write; and whenever the session's PATH (`systemctl --user
show-environment`; the calling shell's PATH if that does not answer) does not
hold Guardian's directory or finds a stock command before it. Turning it on
again writes what is missing, at the end of the file.

### The Bash interceptor

The Bash interceptor catches `omarchy theme install/update` typed in an
interactive Bash, also in a shell whose PATH was reordered or that was not
started from the graphical session (SSH, a console). It passes what it does not
gate to `/usr/share/omarchy/bin/omarchy` by its fixed path; the commands on
PATH also honour `omarchy dev link`. It counts only as the exact line Guardian
writes in `~/.bashrc`, at the top level, with no command before it that leaves
the file, nothing after it that unsets or redefines its functions, and no alias
of one of their names (or of `source`) anywhere in the file. A `return` or
`exit` before it counts as leaving, except in the usual "stop unless this shell
is interactive" line in its common spellings: `[[ $- != *i* ]] && return`, `[[
$- == *i* ]] || return`, `[ -z "$PS1" ] && return`, `[ -n "$PS1" ] || return`,
and `case $- in *i*) ;; *) return;; esac`. The words `return` and `exit` in a
comment, in a quoted string or inside a function or block are not commands;
`<<` in `$(( ))` or `(( ))` is a shift and `<<<` a here-string, neither starts
a here-document.

Guardian reads `~/.bashrc` line by line, not as a shell would: what a file
sourced from it does is not seen.

### Menu overrides

Overrides in your Omarchy menu file
(`~/.config/omarchy/extensions/omarchy-menu.jsonc`, under your home whatever
`XDG_CONFIG_HOME` says, as the menu reads it) point Install › Style › Theme
and Update › Extra Themes at Guardian by its full path. They count when they
are the entries in effect: the menu takes the last entry of an item named
twice, and ignores the whole file when it does not parse.

### Turning them on

Turn them on from the settings app's Integrations tab (or *Protect
everything*); the theme & plugin gate shows as partial while only one of the
interceptor and the menu overrides is in place or in effect. Without the
commands on PATH, `omarchy theme` and `omarchy plugin` typed in another login
shell (zsh, fish) reach Omarchy directly, and the bar says so beside the gate.

Before Guardian first edits one of your files (`~/.bashrc`, `hyprland.lua`, the
Omarchy menu file), it keeps the file as it was beside it as
`<name>.guardian-bak`, once; a later edit never overwrites that copy, and
turning the gate off leaves it.

### Not covered

Not covered:

- a caller that names the stock command by its full path
  (`/usr/share/omarchy/bin/omarchy-theme-install`,
  `/usr/bin/omarchy-theme-install`);
- a program that resets PATH or puts another directory in front (a shell whose
  start-up files do: `status` typed there says so beside the gate);
- a session not started through uwsm and Hyprland (SSH and console logins have
  the Bash interceptor only);
- a theme copied into `~/.config/omarchy/themes` by hand.

The session file and the lines in `hyprland.lua` are your own: a program
running as you can remove them, which the bar then shows and notifies about.

### How a theme is installed

Themes are cloned to a hidden staging directory and reviewed with `guard
--class theme --identity theme:<name> --thorough`; only the exact reviewed
checkout is moved into place and applied. Updates stage and review every
Git-installed theme before replacing any. A theme with submodules is refused,
and so is an update of a theme with local, untracked or ignored files, a
detached HEAD or no upstream branch. Git LFS files are not fetched, so a theme
that uses them gets an incomplete review and is not installed.

## Omarchy plugins

Omarchy shell plugins run as unsandboxed code inside the long-lived
`omarchy-shell`, so `omarchy plugin add` (or `install`) and `omarchy plugin
update` go through `guardian-plugin`:

- **Add:** the repository is cloned to a hidden staging directory and checked
  with Omarchy's own `omarchy-plugin-validate`. It is then reviewed with `guard
  --class plugin --identity plugin:<id> --thorough`, and only when the review
  lets it through (or you gave a permit for exactly that content) is the exact
  reviewed checkout moved into place and, if asked, enabled.
- **Update:** each installed plugin's new commits are fetched into a staged
  copy, fast-forwarded and validated, then reviewed as an upgrade of the
  approved version. The installed plugin is fast-forwarded to exactly the
  reviewed commit, taken from the staged copy rather than fetched from the
  remote again, so a push between review and apply is never installed. Plugins
  with local changes, rewritten remote history or submodules are refused.

Both are gated the same three ways as themes: Guardian's `omarchy`,
`omarchy-plugin-add` and `omarchy-plugin-update` first on the session's PATH
(every caller that finds them by name), the Bash interceptor in an interactive
Bash, and the menu override that points Setup › Plugins › Add Plugin at
Guardian. The same limits apply: a caller using the stock command's full path,
or a program that resets PATH, is not caught, and a plugin copied into
`~/.config/omarchy/plugins` by hand is not reviewed by this gate. `omarchy
plugin clone` copies Omarchy's own built-in plugins and is not gated.
