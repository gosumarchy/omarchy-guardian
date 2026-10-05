# After a block

What you get when a gate blocks, and how to let one blocked install through. A
block comes with a report you can read and ask your AI agent about. A permit
overrules one decision for exactly the content that was reviewed, for 30
minutes; this page says what a permit is bound to, what it can overrule and
what it cannot.

## The report

A block also raises a desktop notification with the Guardian knight. Clicking
it opens the full report as a page in your browser, saved privately under
`~/.cache/omarchy-guardian/reports` (the newest 20 are kept; nothing is saved
when Guardian runs as root). Without Omarchy's browser launcher the
notification only points at the terminal. The page runs no scripts and loads
nothing. Everything quoted from the reviewed code is escaped, and control and
invisible characters are shown as codes, in the page and in the terminal
alike. Its *Ask your AI agent* button opens a terminal that names the report
and waits for Enter, then starts the reviewer set for the `aur` class with the
report: Claude Code for a `claude-code/` model, otherwise OpenCode. The agent
runs with every tool, MCP server and your own agent settings switched off, so
it can only talk. The agent is told that the report is untrusted data. Even
so, take its answer as advice only: never run a command because the report or
the agent quotes it. The report is passed on the agent's command line, which
other local users can read.

## Permitting one install

A review can be wrong. When a gate blocks on something you may reasonably
overrule, its report ends with:

```text
To install this exact content anyway: omarchy-guardian permit 41c9a07d2e556f10b3a8e4d2c7f09a15
  content SHA-256 41c9a07d2e556f10b3a8e4d2c7f09a15c2d7e61f0a9b3c48d5e6f7a8b9c0d1e2  (permit shows it again before it asks: the two must be the same)
```

```sh
omarchy-guardian permit                                    # blocked installs waiting, and permits in force
omarchy-guardian permit 41c9a07d2e556f10b3a8e4d2c7f09a15   # show what is overruled, ask, store the permit
omarchy-guardian permit --revoke 41c9a07d2e556f10b3a8e4d2c7f09a15
```

`permit ID` shows the decision and the review's reasons again, shows the
content SHA-256 root will store, and asks you to type `permit` on the terminal
(there is no `--yes`; without a terminal it refuses). Compare that SHA-256
with the one the gate printed under its permit line before you type the word.
Then it asks for the sudo password and stores the permit. Run the install
again: the gate reviews again, finds the permit, prints `PERMITTED` and which
decision your permit overruled, and goes on. This is meant to replace the
coarse ways out (`protect --off`, `yay --makepkg makepkg`, `ai = "off"`),
which stay on long after the one install they were for.

## What a permit is

- **Bound to the bytes.** The ID is the first 32 hex characters of a SHA-256
  over the gate, the class and the digests of exactly what was reviewed: for
  pacman every archive of the transaction by its class and SHA-256; for a
  theme, a plugin, a `guard` or a `sandbox` the manifest digest of the tree
  (file paths, hashes and execute bits; not where the tree lies or when it was
  written, so a fresh clone of the same commit is the same content); for an
  AUR build the recipe, and for its upstream sources the recipe plus the
  downloaded files by hash. Change one byte and it is other content, blocked
  as before.
- **Short-lived.** A permit ends after 30 minutes. The gates run as you and
  cannot delete root's file, so until then the same bytes pass again: yay
  calls the makepkg gate several times for one build, and all of those calls
  are covered. The pacman hook's root half removes your pacman permits once a
  transaction used one.
- **One gate.** A permit for an AUR recipe or its sources does not cover the
  `pacman -U` that installs the built package: that is another gate and other
  bytes, with its own review and, if it blocks, its own permit. The recipe and
  the upstream sources are reviewed apart, so a build can need a permit for
  each. A recipe permit given before makepkg downloaded into the build
  directory still stands once the downloads are there (by the names the recipe
  writes out); sources that are checkouts rather than downloaded files are
  named by every file, which the build's own `prepare()` changes, so the build
  call may ask again.
- **Root's to write.** Permits are files under
  `/var/lib/omarchy-guardian/permits`, written only through sudo, holding your
  user id, the gate, the class, the content's SHA-256 and the expiry. A permit
  counts only while the file and the directories above it up to `/var/lib` are
  root's and nobody else can write them (the files are world-readable: the
  gates run as you and must read them), and only for the user who asked. A
  permit is given by the user who was blocked, never by root, and one user
  holds at most 32 at a time. What a gate blocked is kept in your own state
  directory for 24 hours (the newest 20 blocks) or until you permit it, and a
  program running as you could write such a record: it still cannot get a
  permit without your typed word and password. Such a program could also put
  other content under an ID a gate printed, if it found some whose SHA-256
  starts with the same 32 characters; that takes more work than anyone can do,
  and the check does not rest on it: the gate prints the whole SHA-256 of what
  it blocked, `permit` shows the SHA-256 root will store, and the two must be
  the same. Permit only an ID a blocked gate printed itself.
- **In the trail.** The grant, each permitted run and a revoke are in
  `omarchy-guardian log`.

## What a permit can overrule

A permit can overrule findings of the local rules and the AI (exit 1), an
incomplete review (a binary the recipe runs, an oversized or binary script, an
unresolved Git LFS pointer, a file withheld from the AI because it looks
sensitive, source too large for the AI review, nothing readable to review, a
dependency check that could not finish, an inconclusive or invalid AI reply),
an unavailable AI under `ai = "required"`, and a `confirm = true` question
that got no yes (answered no, or with no terminal to answer on) when a theme,
a plugin, a `guard`, a `sandbox` or an AUR recipe was reviewed. The AUR gate's
own two questions are another matter: see below. For a pacman transaction the
incomplete reviews it can overrule are those about bytes inside an archive
that was read and fingerprinted: an install scriptlet or auto-run file over 2
MiB or of binary data, more auto-run files than are reviewed, a file the
scriptlet or an auto-run file names that is over 2 MiB, past 500 files, more
than eight files away or past 32 MiB for the package in all, a compiled
program in an auto-run location of a package that is not from an official
repository, and a text file of the archive over 2 MiB that a link already on
this system leads to.

## What no permit covers

No permit is offered, and none is honoured, for:

- what the pacman gate refuses rather than reviews: a package that ships a
  protected path, looks like or claims the place of Guardian or its reviewer,
  an archive that is not a clean package, a transaction it cannot attribute or
  that is redirected (`--root`, `--dbpath`, `--hookdir`, ...), an archive that
  changed during the review, an invalid system config;
- what the pacman gate could not look at outside the archives: a link that
  leads to a file no archive of the transaction ships and root does not keep
  alone, or to one on this system that is over 2 MiB, a directory, or behind
  more than eight links, an auto-run location with more entries than are
  looked through, pacman's record of an installed package that does not say
  what its entry in a directory only root lists is (the message names what to
  remove or reinstall);
- the AUR gate's refusals: a recipe that moves makepkg's directories or lists
  other sources than it writes out, a source that can be replaced in transit,
  sources that are not the ones Guardian fetched;
- a question the AUR gate asked and got no yes to (prebuilt programs, a recipe
  whose sources it cannot follow): that no is yours, and the way to say yes is
  to run the build again from a terminal and answer it;
- any block where part of the content has no digest: a file that could not be
  read or hashed (one over 512 MiB included), a link leading out of the tree,
  a device or other special file, a file name that is not UTF-8, a git
  directory that takes its configuration or hooks from elsewhere, a tree over
  the size limits, upstream sources with unread parts.

## Permits under `strict`

Under the `strict` level permits are off. To allow them there, set in the
root-owned system file:

```toml
[permit]
strict = "allowed"                    # system file only
```
