# What Guardian decided

Guardian records every decision in the system journal, and `omarchy-guardian
log` reads them back. This page says what is recorded, what an entry proves
and what it does not, and how long the trail lasts.

## Reading the log

After an incident this tells you what was installed past which verdict:

```sh
omarchy-guardian log                    # the newest 50 entries
omarchy-guardian log --since yesterday -n 500
omarchy-guardian log --json             # one JSON object a line
journalctl -t omarchy-guardian -o verbose   # the entries as journald keeps them
```

`-n` takes 1 to 10,000; the default is 50. `journalctl -t omarchy-guardian`
also shows what the sweep's timer unit prints; `log` shows only entries that
carry a `GUARDIAN_EVENT`.

```text
2026-10-04 16:14 UTC  you       CLEAR            pacman    ripgrep-14.1.1-1-x86_64  5f0c2a9e41b7
2026-10-04 16:14 UTC  root      PASSED           pacman    the hook's root half: how the review ended  for user 1000
2026-10-04 16:20 UTC  you       INCOMPLETE       aur       aur:demo-bin  9be2f4c01a77
2026-10-04 16:21 UTC  root      GRANTED          aur       permit 41c9a07d2e556f10b3a8e4d2c7f09a15  for user 1000  41c9a07d2e55
2026-10-04 16:22 UTC  you       PERMITTED        aur       aur:demo-bin  permit 41c9a07d2e556f10b3a8e4d2c7f09a15  overrules INCOMPLETE  9be2f4c01a77
```

Each line is the time, who wrote the entry, the decision, the gate, what it
was about, and the first 12 hex characters of the SHA-256 of what was reviewed
(`+N` when there are more, as in a transaction of several archives; `--json`
and `journalctl` have them in full).

## What is recorded

- Every gate decision: each pacman transaction (the archives by name and
  version, each with the SHA-256 of its bytes), each makepkg call of an AUR
  build (the recipe, and the upstream sources when that call reviews them;
  `log` counts repeated lines instead of printing them again), each theme and
  plugin install, and each `guard`, `sandbox` and `scan`. A gate that refused
  before it could review (a redirected transaction, a recipe that changed
  after its review) is recorded as `REFUSED`. A package the pacman gate
  refuses inside a transaction it could otherwise read (a protected path, a
  look-alike name, an archive that changed) is recorded as `INCOMPLETE`, with
  no permit offered.
- The decision's name and exit code, the alert counts by severity, the ids of
  the local rules that matched, how many reasons left the review incomplete,
  the AI review in numbers (model and thinking level, calls, how many were
  clear, suspicious, inconclusive, unavailable or from the cache), the
  protection level and Guardian's version.
- How each scheduled sweep ended (the decision and counts, no names; `FAILED`
  when it could not run), every `sweep allow` and `sweep forget`, every
  `forget`, every `protect` and `protect --off` and every gate switched in the
  settings app, every settings file Guardian saves, `config acknowledge`, and
  every permit given, used or revoked (see [After a block](permits.md)).

The fields are `GUARDIAN_EVENT` (`review`, `permit`, `gate`, `settings`,
`allow`, `forget`, `sweep`), `GUARDIAN_GATE`, `GUARDIAN_CLASS`,
`GUARDIAN_SUBJECT`, `GUARDIAN_DIGEST`, `GUARDIAN_DECISION`, `GUARDIAN_EXIT`,
`GUARDIAN_FINDINGS`, `GUARDIAN_AI`, `GUARDIAN_PROFILE`, `GUARDIAN_VERSION`,
and where they apply `GUARDIAN_PERMIT` (the permit that let a review through),
`GUARDIAN_OVERRULED` (the decision it overruled), `GUARDIAN_OFFERED` (the
permit a block offered), `GUARDIAN_FOR_UID`, `GUARDIAN_CHANGES`,
`GUARDIAN_EXPIRES` and `GUARDIAN_TEST` (an entry written under a test
harness). `log --json` passes on all of these but `GUARDIAN_CHANGES` and
`GUARDIAN_EXPIRES`; `journalctl -o verbose` has every field. No file content,
no excerpt, no AI summary and no address beyond its host is ever written;
names from reviewed content (packages, paths) are written as one bounded line
with control characters shown as codes.

The pacman gate also prints one `sha256` line per archive, so the same digests
are in `/var/log/pacman.log`. Every archive is hashed once for this, the ones
in pacman's cache too: a large system upgrade takes longer by the time it
takes to read every archive once.

## What an entry proves, and what it does not

- No user process can change or remove an entry: the journal files are root's,
  and journald stamps each entry with the user id of the process that sent it
  (`_UID`), which a sender cannot set.
- The column after the time says who wrote the entry: `you`, `root`, `uid N`
  for another user, or `?` when the journal names nobody. `log` makes it from
  journald's own `_UID` and from nothing the sender wrote, and it stands
  before everything the sender wrote. What the sender wrote (a subject, a
  decision's name) is shown on one line with every run of blanks as a single
  one, so it cannot hold the two blanks that part the columns: nothing further
  along a line can pass for that column.
- Guardian's reviews run as you, in the pacman hook too, so their entries
  carry your user id, and **any program running as you can write an entry that
  looks the same**. A `you` line means "written by your user", not "written by
  Guardian". A program that ran as you can add false lines; it cannot take a
  true one away, and it cannot write a `root` line.
- A `root` line was written by a process running as root. Guardian's root
  halves write these: the pacman hook script records how each review ended
  (`PASSED`, `PERMITTED` or `BLOCKED`) after the review process, which runs as
  you, has exited, and permits and the sweep's allow list are written through
  sudo. Guardian run with sudo, or anything else root runs, writes `root`
  lines too. No process without root can. A pacman install with a `root` line
  and no review line beside it, or the reverse, is worth a look.
- At the end of a line, `log` marks an entry that did not arrive the way
  Guardian sends them, through `/usr/bin/logger` to journald's own socket
  (`[! not written as Guardian writes]`), and one written under the test
  harnesses (`[test]`). The absence of the first mark proves nothing: any
  program can call `logger` too.
- Entries written by root are in the system journal, which only root and
  members of the `systemd-journal`, `adm` or `wheel` group can read; run `sudo
  omarchy-guardian log` otherwise. Under sudo your own entries are shown as
  `uid N`, not `you`.
- The user gates (AUR, themes, plugins, `guard`) are programs you run:
  something that installs without calling them leaves no entry. Only the
  pacman hook runs inside the install itself: every pacman or libalpm
  transaction that installs or upgrades a package runs it while the hook is
  turned on. Root can turn it off (`protect --off` is recorded), and files put
  in place without pacman pass no gate.

## How long the trail lasts

journald decides. By default the journal under `/var/log/journal` keeps up to
10% of its filesystem (at most 4 GiB) and drops the oldest entries first; a
program that writes a great many entries pushes older ones out sooner. To keep
more (`SystemMaxUse`), and to drop what is older than a set time
(`MaxRetentionSec` removes older entries; it does not promise to keep newer
ones):

```ini
# /etc/systemd/journald.conf.d/guardian.conf
[Journal]
Storage=persistent
SystemMaxUse=8G
MaxRetentionSec=1year
```

then `sudo systemctl restart systemd-journald`. Guardian keeps no log file of
its own.
