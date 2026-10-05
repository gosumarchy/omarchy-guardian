# Commands

What `scan`, `guard`, `sandbox`, `sweep`, `permit` and `log` do, the options
they share, and the exit codes. The commands that change settings (`setup`,
`config`) are described under [Settings](settings.md#settings-commands),
`protect` under [Install](install.md#turning-protection-on), and `status`
under [The bar and `status`](settings.md#the-bar-and-status).

## Reviewing by hand

```sh
omarchy-guardian scan ./downloaded-project
omarchy-guardian scan --thorough --hashes ./theme-checkout
omarchy-guardian guard --thorough ./aur-build-directory -- makepkg --noconfirm
omarchy-guardian sandbox ./theme-checkout -- /usr/bin/true
omarchy-guardian sweep
```

- `scan` reviews a file or directory and prints a report.
- `guard` reviews, then re-hashes the tree, then **replaces itself** with the
  command (`exec`) only if the review was clear or warned and nothing changed.
  A warned review is one with something left unread that the class's settings
  allow: an unavailable AI review under `ai = optional`, or a skipped tool
  directory (see [what is
  read](review.md#what-is-read-and-what-makes-a-review-incomplete)).
  `--exclude NAME` (repeatable) leaves a top-level directory (never a file or
  link of that name) out of both the review and the snapshot.
- `tui` (or `settings`) opens the settings app: a full-screen terminal UI in
  Omarchy's style, simple by default, with every setting under `--expert` (see
  [Settings app](settings.md#settings-app)).
- `sandbox` reviews, copies the tree (without `.git`) to a private temporary
  directory, proves the copy matches the reviewed snapshot, and runs the
  command in Bubblewrap with the network isolated, no host home directory and
  a read-only system. It is a behaviour smoke test, not a dynamic malware
  detector.
- `sweep` checks what already runs on its own on this machine (see [System
  sweep](system-sweep.md)). `--root` also checks what only root can read now,
  `--all` lists trusted items too, `--diff` only what changed since the last
  sweep, `--json` prints one JSON document. `sweep allow PATH` trusts one item
  as it is now; `sweep forget PATH` (or `--all`) undoes it. Both ask for the
  sudo password: the list of allowed items is root's.
- `--identity ID` or `--unit DIR ID` (repeatable) on `scan`, `guard` and
  `sandbox` name what is reviewed for the review memory (see [Review
  memory](review.md#review-memory)); `omarchy-guardian forget ID` drops that
  source's baselines (cached verdicts are kept) and what the AUR gate
  remembers of it (the questions you answered, its binaries, what was
  extracted), and `forget --all` clears everything.
- `permit ID` lets one blocked install through, for exactly the content that
  was reviewed (see [After a block](permits.md)); `permit` alone lists what
  can be permitted, `permit --revoke ID` takes a permit back.
- `log` shows what Guardian decided, from the system journal (see [What
  Guardian decided](audit-trail.md)): `--since TIME`, `-n N`, `--json`.

## Exit codes

`0` clear, warned, limited review (a scriptlet-free pacman transaction) or
permitted; `1` findings; `2` an incomplete review, an unavailable AI review
under `ai = required`, a question that got no yes (`NOT CONFIRMED`), a
settings file that does not parse, or a usage error. `guard` and `sandbox`
never exit `0` without having started the command: a review with nothing to
review exits `2` there. Once `guard` or `sandbox` starts the command, the exit
code is the command's own (128 + signal if it was killed). Guardian announces
on stderr when it starts the command, so its own blocks can be told apart from
the command's failures. The full table is under [Decisions and exit
codes](settings.md#decisions-and-exit-codes).
