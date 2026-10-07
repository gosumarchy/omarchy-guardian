# AUR gate

The AUR gate reviews an AUR build before any of it runs: the recipe (PKGBUILD)
first, then the upstream sources. Its mechanism is a shim that yay calls in
place of `makepkg`; the shim runs `omarchy-guardian makepkg-gate`, which this
page calls the makepkg gate. The page goes through the gate's steps in order,
then says what is not reviewed and where the gate's output goes.

## Contents

- [Overview](#overview)
- [What the gate does, in order](#what-the-gate-does-in-order)
- [What is not reviewed](#what-is-not-reviewed)
- [What the gate prints](#what-the-gate-prints)

## Overview

The recipe (PKGBUILD) is reviewed before any of it runs. Its sources are then
listed in a sandbox with no network (the recipe's top-level code runs there
and nowhere else before the build), fetched and unpacked from a recipe
Guardian writes itself (no code of the package runs: not `pkgver()`,
`prepare()`, `build()` or `package()`), and reviewed before anything is built.
yay's first call, which only downloads and verifies, is the exception: there
makepkg runs the reviewed recipe and its `verify()` as you. Plain-HTTP sources
without checksums block, and the AUR's own trust signals (age, votes,
maintainer changes) are part of the review. A package made of prebuilt
programs, or a recipe whose sources Guardian cannot follow, is not waved
through: Guardian says so and asks on the terminal.

## What the gate does, in order

The yay shim runs `omarchy-guardian makepkg-gate` in the AUR build directory
before every `makepkg` call. yay calls makepkg several times per package; the
gate does, in order:

### Step 1: AUR trust signals

When the build directory is a clone of an AUR package (its git origin is
`https://aur.archlinux.org/<name>.git` and the directory has that name), the
package is looked up in the AUR RPC. Only that name and the names in the
PKGBUILD's `pkgname=` lines are sent. Any other directory gets no AUR facts,
and Guardian says so. The package's age, votes, maintainer and submitter are
printed, and a package first submitted under 30 days ago, with fewer than 5
votes, orphaned, or changed in the last 14 days by a maintainer who did not
submit it is flagged. These are warnings, and are given to the AI review as
facts. A package with fewer than 5 votes is also held against known names: the
official packages in pacman's own databases on this machine, and AUR packages
with at least 50 votes found by one AUR search (only the name without its
ending, or its first two thirds, is sent). A name that is a known one with
another ending (`-bin`, `-git`, `-patched`, `-patch`, `-fixed`, `-fix`), or a
letter or two from one, is flagged; AUR malware has arrived under such names
(`firefox-patch-bin`). The one search finds a look-alike of an AUR package
only when the names share their first two thirds. The AUR is asked for the
package's record a second time over IPv4 if the first try fails (it has
answered there while dropping IPv6 connections). When the AUR cannot be
reached, the build goes on, and both you and the AI are told that the signals
are missing, not that they are fine. The package's history in its AUR
repository is not read: that would mean running git in the build directory,
which Guardian never does.

### Step 2: The recipe

The PKGBUILD, install scripts, patches and other AUR files are reviewed as
`guard --class aur --thorough --exclude src --exclude pkg` would. The AI is
told that upstream sources are reviewed in the next step, that prebuilt
binaries cannot be reviewed by anyone, and what routine packaging looks like.
A PKGBUILD's `url=` and `source=` entries are declarations, not network
requests, for the local rules, unless they run a command.

### Step 3: Sources

This step and the next are skipped for a call that only prints information
(`--packagelist`, `--printsrcinfo`, `--version`, `--help`). Generating
checksums (`-g`) downloads the sources, so it is covered. Only now, with the
recipe reviewed, the gate has makepkg list the sources in a sandbox (described
under step 4), reads the recipe's text for how it arrives at them, and asks if
it cannot follow that. Then it checks the listed sources:

- a download without a checksum, or a repository not pinned to a full commit,
  over an unencrypted connection (`http://`, `ftp://`, `git://`, `git+http://`)
  blocks the build, since anyone on the network path can replace it. That holds
  for a call that builds from sources extracted earlier (`--noextract`) too;
  only a call that downloads and stops, such as `--verifysource` or `-g` to
  generate the missing checksum, is warned;
- a repository fetched over an encrypted connection that is not pinned to a
  full commit (a branch, a tag, a short or symbolic revision; `commit=` or
  `tag=` with a checksum counts as pinned), or a download over HTTPS without a
  checksum, is a warning.

### Step 4: Upstream code

The listing and the fetch are two makepkg runs inside a Bubblewrap sandbox (the
system read-only, your home directory empty apart from makepkg's own
configuration). The listing is made on every call that runs the recipe's
functions; the fetch only when the call extracts the sources:

- *Listing the sources* (`makepkg --printsrcinfo`). This reads the PKGBUILD,
  whose top-level code can run anything, so it gets no network and nothing of
  yours to write to: the recipe's directory is read-only. makepkg's build and
  download directories are given names made up for the run, and a recipe that
  has changed either by the end of it is refused. What the recipe prints while
  it loads is kept out of the listing, and a listing that is not shaped as
  makepkg prints one (text before its first line, a second package base, a
  line of another form) is refused. Sources are read from the package base's
  section only. The listing run is not given your proxy settings; the fetch is.
- *Fetching them.* The PKGBUILD does not run here at all. makepkg is given a
  recipe Guardian writes from that listing: the sources, their checksums, what
  not to extract and the signing keys, each as quoted text, and no code. It
  downloads, verifies and extracts as it would for the real recipe, with the
  network on, a copy of your public gpg keyring (for source signatures; never
  the private keys), and write access only to the recipe's directory and the
  build and download directories your makepkg configuration names. An existing
  `src/` is removed first.

So in this step the recipe's code only runs where it has no network and can
write nothing but scratch files that are thrown away, upstream code does not
run at all, and what is reviewed is what makepkg extracted from the downloads
the build will use. This holds for the call that extracts. A helper such as
yay first makes a call that only downloads and verifies (`--verifysource`):
there the real makepkg reads the recipe, and runs its `verify()`, as you, with
the network, after the review of the recipe's text alone (steps 1 to 3).
Guardian refuses:

- a recipe that sets one of makepkg's own directories at its top level
  (`BUILDDIR`, `SRCDEST`, `PKGDEST`, `SRCPKGDEST`, `LOGDEST`, `startdir`,
  `srcdir`, `pkgdir`, `BUILDFILE`, `MAKEPKG_CONF`). This is refused first,
  before the review, on every call;
- a source kept under a name that is a path (`a/b::…`, `../x::…`), which
  makepkg would write outside the downloads;
- a version-control source whose checkout already exists, in the recipe's
  directory or the download directory, and is not a plain git mirror as makepkg
  makes one (other configuration, hooks, or another tool's checkout): makepkg
  would run that tool inside it. Remove the directory to fetch the source
  afresh;
- a recipe of an AUR package whose `pkgbase` is not that package;
- fetching when the recipe's directory, or the build or download directory your
  makepkg configuration names, is or contains your home directory, `/usr`,
  `/etc` or the temporary directory, or lies under `/usr` or `/etc`.

A source that needs your SSH keys (`git+ssh://`) cannot be fetched in the
sandbox: the fetch fails and the build is blocked.

The fetch has the network, so it can reach services on this machine and your
local network like any download.

**A recipe can tell that it is only being listed.** The listing run is made to
look like an ordinary one as far as that is cheap: makepkg is called on a file
named `PKGBUILD` in the recipe's directory, no variable of Guardian's is in
its environment, and the package directory is one a user's own setting could
name. A recipe that looks can still tell: there is no network, its directory
is read-only, the home is empty, and the file it is loaded from is a copy in
the temporary directory. So the listing alone proves nothing about the build,
which loads the recipe again. Guardian therefore reads the recipe's text for
how it arrives at its sources, checksums, `noextract`, signing keys and
makepkg's directories, and sorts it into one of three:

- *Written out.* Each array is set once, at the top level, in plain words,
  with at most variables the recipe itself sets to plain text (`$pkgname`,
  `$pkgver`, `$_commit`, `$url`). The listing must then give exactly those
  arrays, or the build is blocked as incomplete.
- *Worked out the same way everywhere*: an expansion Guardian does not repeat
  (`${pkgver%.*}`), `+=`, an element set by its number (`sha256sums[2]=SKIP`),
  a `case`, an `if` or a test that compares `$CARCH` or values the recipe
  writes out (`[[ $pkgver == *rc* ]]`), a loop over a written-out list.
  Nothing more is asked.
- *Not followed*: everything else. It comes to four kinds:
  - A source, or anything a source is built from or depends on, that can differ
    between two runs: a test that looks at a file (`[[ -w . ]] && source=(…)`),
    a command's result or output, a pattern for file names (`*.patch`), `~`, a
    variable the recipe does not set (`$HOME`, `$DISPLAY`, an option read from
    the environment) or that bash fills in (`$RANDOM`, `$PWD`), arithmetic on
    anything but a plain number, a variable set in a subshell, a pipe or for
    one command only.
  - A watched variable set indirectly: in a function the top level calls, or
    through `eval`, `printf -v`, `read`, `mapfile`, `getopts`, `let`, `((…))`,
    a `for` loop, `declare`/`typeset`/`local`/`export` (`-n` and `-i` included)
    or `${name:=…}`, however the name is quoted.
  - A command Guardian cannot name, or code read in or run while the recipe
    loads: a command named in quotes, with a backslash or by a variable; one of
    makepkg's own functions; `source`, `.`, `trap`, `alias`, `exec`; an early
    `exit` or `return`; `DLAGENTS`; a function named like a command; a process
    substitution; a line of `package()` that sets an attribute and something
    else beside it (makepkg runs such lines while it loads the recipe).
  - Text Guardian may read otherwise than bash does: a here-document whose text
    bash expands, and quoting Guardian is not sure it reads as bash does.

  The reasons are printed with their lines (up to eight), the AI is told as a
  fact, and you are asked on the terminal whether to go on. No terminal, or no
  yes, blocks the build (exit 2, NOT CONFIRMED); with no terminal Guardian says
  that it needed one and raises a desktop notification, so a build started from
  a graphical front end does not just stop. A yes is remembered for that exact
  recipe (the PKGBUILD and every file beside it, which it could read its
  sources from), so yay's further makepkg calls and a rebuild do not ask again;
  a changed recipe does. The values of the `pkgver=` and `pkgrel=` lines are
  left out of that: a `pkgver()` function has makepkg rewrite them between two
  calls of one install.

Most recipes are not asked about (measured on 4 October 2026 on a sample of 400
AUR recipes: 14 were asked about). The ones that are take sources or checksums
from a command's output or from options read out of the environment, or use
`eval` or `DLAGENTS`. This reading is not a shell: text that bash reads
otherwise than Guardian does could still hide an assignment, and the recipe is
reviewed by the AI as well. Nothing stands between the listing and the build
beside it: the real makepkg loads the recipe again, outside the sandbox, and
fetches what the recipe tells it then.

What Guardian extracted is remembered (every file and download with its hash).
A later call for the same build that does not extract (`--noextract`, yay's
build call) is held against it before makepkg starts: a download that is new
or not the one Guardian fetched blocks the build, and so does a source
directory that is still the one Guardian made although the build was to clean
and extract it again (`-C`): the build's own extraction and `prepare()` then
ran somewhere else. Files that are new or changed in `src/` (what the build's
own extraction, `prepare()` and `pkgver()` left) are reviewed before other
code, and you and the AI are told how many there are. This catches a recipe
that listed one thing and built another only after its `prepare()` and
`pkgver()` ran on what it really fetched: Guardian hands the call that
extracts over to makepkg and cannot look in between. The call that extracts is
handed to makepkg with `--holdver` added, so it does not fetch newer VCS
sources than were reviewed.

With no such record because Guardian did not extract for this build, the
sources are reviewed as that call finds them, and you and the AI are told so.

Where there should be a record and there cannot be one, the build is blocked
(exit 2) and the message says what to put right:

- Guardian keeps these records in `aur-gate` under its review memory
  (`$XDG_STATE_HOME/omarchy-guardian`, else `~/.local/state/omarchy-guardian`),
  a directory that must be yours alone. If it or the directory above it is
  open to group or others, belongs to another user, has a link or a file in
  its place, or cannot be made, or if neither variable names a place, a call
  that extracts or builds from what was extracted is blocked before anything
  is reviewed or fetched. A directory that was open to others is not to be
  closed and used as it is: someone else may have put records in it. The
  message gives the commands to close it and drop what it holds, or to remove
  it. Calls that only print (`--printsrcinfo`, `--packagelist`) still work.
- If the record cannot be written (a full disk, a directory you cannot write
  to), the call that extracts is blocked. A record of an earlier extraction
  stays as it was.
- If the record is there and cannot be read back, or a directory is in its
  place, the later call is blocked. Extracting again writes a new record; a
  directory that is not empty you remove yourself.
- If the sources have more files, or longer names, than a record can hold, the
  build is blocked at both calls.

An answer of yours that cannot be remembered, or binary hashes that cannot be
kept, do not block: Guardian says so, and asks again at the next makepkg call.

The AI then reviews the upstream code under `src/`: all of it when its code is
up to 1 MiB. A larger source is reviewed in part: its build files and scripts
(makefiles, CMake, meson, `configure`, `setup.py`, `build.rs`, `package.json`,
shell scripts…) are always sent, then files changed since Guardian extracted
the sources, then other code by depth, up to the `aur` class's `max_input_kib`
× `max_chunks` (2 MiB with the defaults, never less than 1 MiB). If the build
files and scripts alone exceed that, the review is incomplete. Code that a
build file names (`"postinstall": "node tools/a/b/gen.js"`, a makefile that
runs `lua`, `ruby`, `awk` or `php` on a file, or reads one in with `include`)
counts as a build file however deep it lies. Data and documentation (`.json`,
`.md`, `.txt`…) are left out, and so is a file over 2 MiB that is not a build
file or script (a bundled `.js`, say). Every file left out, for its kind or
past the budget, is kept by name: if a reviewed line runs or reads in such a
file, or a binary (`sh ./NOTES.txt`, `sh ./tool.bin`, `node big.js`), the
review is incomplete, and so it is when one of the recipe's own functions or
install scripts runs or reads in a text file that was left out. A binary the
recipe itself runs is asked about in step 5 instead.

Dependency lockfiles and manifests (`package-lock.json`, `yarn.lock`,
`pnpm-lock.yaml`, `Cargo.lock`, `go.sum`, `go.mod`, `requirements*.txt`,
`poetry.lock`, `Pipfile.lock`…) are always read: Guardian scans each one
itself, whatever its size, for addresses outside the ecosystem's registry,
version-control and unencrypted addresses, install scripts and lines that
point a dependency elsewhere, prints what it found and tells the AI in its own
words; the file itself is sent too when it is up to 64 KiB (a larger one would
use up the review); one over 64 MiB is not read, and the review is incomplete.
Code under `node_modules`, `__pycache__`, `.venv`, `vendor`, `third_party`,
`test`, `tests`, `doc`, `docs`, CI directories (`.github`, `.gitlab`,
`.circleci`), `.devcontainer` and another version-control tool's metadata comes
after other code of the same rank.

git's own objects are not source, but git and Mercurial run what their metadata
says on the commands a build often uses (`git describe`): a `.git` whose
configuration names a command or another address for git to fetch from (hooks
defined there included) or that holds live hooks (its submodules under
`.git/modules` included, and a repository laid out under another name), one
given as a file or a link, one with a `commondir`, and an `hgrc` with hooks,
extensions, aliases, external diff or merge tools, or an include make the
review incomplete (a checkout makepkg made has none of these, unless your own
git template directory installs hooks). A file placed at the top of `.git` that
git does not keep there, and every file in a `.svn`, `.hg` or `.bzr`
directory, is reviewed like the rest of the sources. A file or directory whose
name is not UTF-8 is read and reviewed like any other.

An archive the build opens itself (listed in `noextract`, or found inside the
sources and named by the recipe or given by it to `bsdtar`, `tar`, `unzip`,
`ar` and the like, such as the `data.tar.xz` of a `.deb`) is unpacked by
Guardian first, beside `src/`, with `/usr/bin/bsdtar` in the same sandbox (no
network, nothing writable but the directory unpacked into), and its files are
reviewed like the rest, under the archive's path followed by `!`. Up to eight
archives are unpacked, one inside another at most, each up to 2 GiB and 100,000
entries. An archive the recipe opens that is not unpacked (it holds a device
file, a pipe or a socket, is past those limits, is the ninth, lies deeper, or
cannot be read by bsdtar) makes the review incomplete. An archive the recipe
does not name stays packed and is named as not reviewed, up to five of them.

The review looks for malicious intent in what runs during the build and in the
program's own code, not bugs or vulnerabilities, and is told whether the
recipe runs the test suite (`check()`).

The upstream review is remembered as `aur-src:<package>`, so a new version is
reviewed as a diff, unless a binary file in the unpacked sources was added,
changed or removed (they are hashed; the downloaded archives themselves are
not counted, since their names change with every version): then the code is
reviewed in full and the AI is told which binaries differ. Guardian also keeps
the hashes of the binaries of the last build it let through, with or without
text beside them, and says which are new, changed or gone.

`omarchy-guardian forget aur:<package>` drops the recipe's baseline and what
this gate remembers of the package (your answers, the binary hashes, what it
extracted); `forget aur-src:<package>` drops the upstream baseline and the same
records. Cached verdicts are kept.

### Step 5: Prebuilt programs

Sources with no text to review are not a clear review. When a package is made
of prebuilt programs (the recipe has no `build()` and its sources, or an
archive it opens, hold programs), or the recipe's functions or install scripts
name or run a program from the sources, Guardian says so plainly, for example
`this package installs 3 prebuilt program(s) nobody reviewed, downloaded from
github.com`, names them, and asks on the terminal. A program here is machine
code or bytecode, and also code that comes packed and is installed as it is: a
Java archive, an Electron `app.asar`, a browser extension, a `.deb`, `.rpm` or
pacman package that Guardian did not unpack for review (also `.war`, `.apk`,
`.whl`, `.gem`, `.phar`, `.vsix`, AppImage, snap, flatpak and `.msi` files). No
terminal, or no yes, blocks the build (exit 2, NOT CONFIRMED), and no permit
overrules a question you declined: the way to say yes is to answer it. A permit
that overrules the review of the sources does not answer it either: it is for
the review's verdict, and the question is asked all the same before the build
goes on. A yes is remembered for exactly those programs (their hashes) from
those hosts, and for which of them the recipe runs, so yay's further makepkg
calls and a rebuild of the same version do not ask again. A build whose
programs, hosts or run programs differ is asked again, which a new version of a
prebuilt package nearly always is. A program too large to hash is asked about
every time. A source tree that is built and only carries a binary among its
test data is not asked about. The question is asked on `/dev/tty`, after the
review, and never replaces it.

### Step 6: makepkg

The recipe is checked once more against what was reviewed; a change blocks.
makepkg then starts with the original arguments (plus `--holdver` on a call
that extracts), with `BUILDDIR` and `SRCDEST` set to the directories your
makepkg configuration names.

## What is not reviewed

What is not reviewed is reported: how many code files were left out, and that
data files were skipped. Prebuilt programs cannot be reviewed by anyone; step
5 makes that your decision instead of a silent pass.

The upstream code of step 4 is judged by the AI: the local rules read the
recipe and the files beside it (step 2), and a source tree is full of ordinary
uses of what they name (a program that starts another, an install script
quoted in the project's own tooling). Two local checks read the upstream code
even so, since they are about what the reviewer and you are shown: invisible
tag characters and text reordered with bidirectional controls are findings
(they block under the stock settings).

With the AI review off for AUR builds (`ai = "off"`, or the `local-only` level)
the upstream code would pass unread, so there the local rules read it too,
keeping their high findings only (download and run, encoded commands,
destructive commands, credential exfiltration, a remote shell, a miner, a
protection turned off, text for a reviewer, tag characters and reordering
controls): much less than a review. Documentation files among the sources are
not read by the command rules there. The sources are still fetched in the
sandbox, held against what was extracted, and the questions about a recipe
Guardian cannot follow and about prebuilt programs are still asked. Under
`local-only` the recipe step asks as well, since no AI review ran.

Dependencies a build downloads on its own during `prepare()` or `build()`
(cargo crates into `~/.cargo`, npm packages into `~/.npm`, Go modules into
`~/go`, pip, and the like) are **not reviewed**: they are not among the
sources. When the sources hold a manifest or lockfile, Guardian warns and
tells the AI so; the lockfile scan above covers where they come from, not what
they contain.

On a call that only verifies sources (`--verifysource`), the real makepkg runs
the recipe's `verify()` on the downloads before any upstream review: only the
review of the recipe covers that function.

The gate refuses `--file`/`-p` and `--dir`/`-D` in any spelling makepkg accepts
(inside a cluster such as `-fp`, with the value attached, or shortened), and a
shortened `--config`, since it reviews the recipe in the working directory with
the configuration it was given.

## What the gate prints

Everything Guardian prints in the makepkg gate goes to standard error, on
every makepkg call. Standard output is left to makepkg: yay reads the package
list from it (`makepkg --packagelist`), and a line of Guardian's there would
be taken for a package name.
