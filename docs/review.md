# Review

How a review is made: the local rules and the AI review, what is read and what
makes a review incomplete, how the reviewer (OpenCode or Claude Code) is run
and what stays outside Guardian's control, how large sources and upgrades are
reviewed, and the review memory. The local checks have a page of their own:
[Local rules](local-rules.md).

## Contents

- [Two reviews](#two-reviews)
- [Fail closed](#fail-closed)
- [What is checked](#what-is-checked)
- [What the reviewer's reply decides](#what-the-reviewers-reply-decides)
- [What is read, and what makes a review incomplete](#what-is-read-and-what-makes-a-review-incomplete)
- [How the reviewer is run](#how-the-reviewer-is-run)
- [How the review scales](#how-the-review-scales)
- [Review memory](#review-memory)
- [Using Claude Code as the reviewer](#using-claude-code-as-the-reviewer)

## Two reviews

Fast local rules flag known-bad patterns (download and execute, privilege
escalation, persistence, credential access and exfiltration, encoded commands,
destructive operations). An AI reviewer then reads the code with every tool
switched off and must echo a one-time nonce given after the code, so a reply
that never read to the end of the code cannot pass as a review. The code can
still try to talk the reviewer into a clean verdict, which is one reason the
local rules always run too and a clear result is not a guarantee.

## Fail closed

A review that cannot finish blocks. An unavailable AI blocks every class whose
`ai` setting is `required` and warns where it is `optional`. In the stock
profiles only official Arch/Omarchy updates under `standard` are optional. A
question nobody can be asked (no terminal) is answered no. A settings file
that does not parse stops the gates that read it instead of being skipped; a
broken system file stops them all.

## What is checked

- **Local rules, network destinations and dependencies:** the checks that run
  on the machine itself, described under [Local rules](local-rules.md).
- **AI review:** the reviewable text is sent, in chunks of up to
  `max_input_kib` (default 256 KiB, at most `max_chunks` per review, default
  8; see [How the review scales](#how-the-review-scales)), to the reviewer CLI
  (OpenCode or Claude Code) **on stdin** (never in argv, which is size-limited
  and visible to other users) with every tool and permission of that CLI
  denied. The reply must echo a random per-run nonce that only exists in that
  input and is given after the source, so a reply that never saw the source,
  or stopped reading part-way, is rejected. The nonce shows the reply came
  from a model that was given this request; it cannot show how carefully the
  source was read. In the request, every invisible or text-reordering
  character of a file or a file name (control characters, zero-width and
  bidirectional marks, variation selectors, Unicode tag characters) is written
  as a `\u` escape: the model sees which character was there, none reaches it
  raw, and none can draw a line that looks like the end of the data. No
  character of a file that is sent is removed or masked. The reply may also
  say that the content speaks to its reviewer (an instruction, a verdict, a
  nonce, a reason to stop reading, in a comment, a string, a document or a
  file name). Guardian then adds a high finding of its own and the review is
  not clear, even if the same reply says `clear`: a model that was talked into
  a verdict is not taken at its word. A reply without that field is read as
  before. A finding written a little off the asked shape is kept, not dropped:
  a severity Guardian cannot read counts as high, the first of several files
  named stands for the finding, and a line given as `3-5` is read as 3. Only a
  finding that is not a JSON object makes the reply invalid. Files that look
  sensitive by path (`.env`, `.env.*`, `*.env`, `*.tfvars`, `*.tfstate`,
  anything under `.ssh`, `.aws`, `.gnupg`, `credentials` or `secrets`, key and
  keystore files, `.netrc`, `.pypirc`, `.kube/config`, names containing
  `secret` or `credential` or the word `token`; `.envrc` and `.npmrc` are
  sent) are withheld and make the review incomplete.
- **Integrity:** a SHA-256 manifest of every scanned file. `guard` and
  `sandbox` re-hash immediately before running the command.

## What the reviewer's reply decides

Each chunk's reply carries a verdict (`clear`, `suspicious` or `inconclusive`)
and a list of findings, each graded `high`, `medium` or `low`:

- `inconclusive`, or a reply Guardian cannot take as a review, leaves the
  review `INCOMPLETE`.
- `suspicious`, with or without findings, follows `on_ai_suspicious`, which
  is `block` in every profile. So does any finding graded `medium` or `high`,
  whatever the verdict beside it.
- A `clear` verdict whose findings are all graded `low` says that nothing in
  the chunk means harm to you, and adds what the reviewer noticed all the
  same: a download with `curl -k` in upstream code, an unquoted variable in a
  message. Under `standard` and `local-only` these are **remarks**. The report
  lists them in full under "AI remarks" and counts them apart from the alerts,
  and they decide nothing: the decision is what it would be without them
  (`CLEAR`, or what the local rules, advisories and gaps make it), the install
  goes ahead, and no notification is sent and no permit offered on their
  account. Under `strict` they are findings like any other and follow
  `on_ai_suspicious`.

One finding of a chunk graded above `low`, or one whose severity Guardian
cannot read (it counts as high), and every finding of that chunk is a
finding. Each chunk is judged on its own: the remarks of one take nothing
from a `suspicious` verdict or a higher finding in another, which block as
they always did. Where a pacman transaction holds packages of several
classes, a chunk's low findings are remarks only when every class it touches
(its files, and each file a finding names) shows them as remarks.

What remarks are comes with the profile and is not a setting: no settings
file can change it for a class. For the pacman classes the stricter of the
system's profile and your own holds, as for the other values. `config show`
prints it as `low AI remarks`.

A review that is clear with remarks is remembered like any clear review (see
[Review memory](#review-memory)): the verdict is cached with its remarks, so
the same content shows them again from the cache, and the source becomes the
approved baseline. The audit trail records how many there were
(`remarks=N`).

The [system sweep](system-sweep.md) is not a gate and lists what there is to
look at: there every AI finding on an item is a finding in every profile, the
low ones of a clear verdict included.

## What is read, and what makes a review incomplete

The walk never follows symbolic links, including ones swapped in while it
runs: directories are read through verified `/proc/self/fd` handles and every
opened file is checked against its earlier `lstat`. A relative symlink to a
file or directory inside the tree that the review covers (such as the
`LICENSES/0BSD.txt -> ../LICENSE` many AUR packages carry) is recorded by its
link text, so retargeting it changes the snapshot, and its target is reviewed
where it is. Other symlinks (absolute, leaving the tree, dangling, through
another link or into a skipped directory), special files, non-UTF-8 file
names, text files over 2 MiB, files over 512 MiB, unresolved Git LFS pointers
and an invalid or inconclusive AI reply all make the review **incomplete**,
never clear. A tree of more than 200,000 files, 256 MiB of text or 4 GiB in
all is not walked to its end, and one with no text file to review has nothing
reviewed: both are incomplete.

An *unavailable* AI review (no reviewer CLI, a provider error, a timeout)
follows the class's `ai` setting instead: `WARNED` where it is `optional`,
blocked (`AI UNAVAILABLE`) where it is `required`. With the stock profiles
that is `WARNED` for `official` under `standard` and blocked everywhere else.
A provider that answers that the request is too long for the model is not
unavailable: the review is invalid, which blocks as `INCOMPLETE` in every
class. So is one that refuses what it was sent (a usage-policy or safety
refusal, a content filter, a guardrail): a source can be written to be
refused. A network or login error, a rate limit and an overloaded provider
stay unavailable. A run that times out before the model starts on the source
is unavailable. One that times out after the model had it is not, since a
source can be written to keep a reviewer busy: that review is invalid too,
except for the `official` class, whose content nobody writing such a source
chooses, where it counts as unavailable.

In `.git`, only the `config` (checked locally for keys that make git run a
command, such as `core.fsmonitor`, filters and `!` aliases, and never sent to
the AI; also `config.worktree`) and hooks other than git's `.sample` files are
reviewed. Submodules kept under `.git/modules` are read the same way, nested
ones included (past six levels the review is incomplete). A directory laid out
as a repository under another name is read the same way too. Its `config` is
checked like a `.git/config` and also reviewed like any other file (a build
could run it as something else), with two things taken out first: the user and
password of every address, and an `extraHeader` login (`Authorization: basic
…` that decodes to a plain `user:password`). Other values are kept whatever
their key is called, since a value can be code or name what a file runs:
another token written there (a bearer token, say) is seen by the AI provider,
and so is a password with characters other than letters, digits and
`._~%+=-:`. A `.git` given as a file or a link, a linked `config`, hooks or
submodules behind a link, a `commondir` (which makes git read another
directory's configuration and hooks), and such a `config` that cannot be read
make the review incomplete: git would read them and the review cannot.

A file that opens like a known binary format or a UTF-16 mark but is plain
lines of text is reviewed as text, and text with a NUL byte after its first
line is not passed over as binary: it makes the review incomplete. A file with
a UTF-16 mark is read as UTF-16 only where that gives mostly ASCII text;
otherwise it is read by its bytes, which for UTF-16 text in another script
means hashed only. A file that opens like a known format and holds NUL bytes
near its start is taken as that format and only hashed, even if text follows;
if a reviewed script runs or reads it in, the review is incomplete (see [Local
rules](local-rules.md#across-lines-and-files)).

A top-level `target`, `node_modules` or `.venv` that carries its tool's marker
file (`CACHEDIR.TAG`, `.package-lock.json`, `pyvenv.cfg`…) is skipped unless
`--thorough` is given; the skip is listed under "Not reviewed", its file count
is part of the snapshot, and the review is then at best `WARNED`. `vendor`,
`dist` and `build` are shipped code and always reviewed.

## How the reviewer is run

External helpers are run by absolute path (`/usr/bin/curl`, `/usr/bin/bsdtar`,
`/usr/bin/pacman`, ...) with a timeout and bounded output. The reviewer CLI is
looked up in the absolute entries of `PATH` for every user-level gate (`scan`,
`guard`, `sandbox`, the AUR gate, and through `guard` the theme and plugin
gates). The pacman hook only accepts a root-owned `/usr/bin/opencode` or
`/usr/local/bin/opencode` (for Claude Code, `/usr/bin/claude` or
`/usr/local/bin/claude`), because it gates a root transaction and a
user-writable reviewer could be replaced by user-level malware. A reviewer
found on `PATH` is refused, with the reason, when it or its directory can be
written by group or others, or when it lies under `/tmp`, `/var/tmp`,
`/dev/shm` or your cache directory (also behind a link). The reviewer must
have a working provider or login; source leaves the machine through it.

The reviewer is given as little besides the request as its CLI allows.
OpenCode runs from a new, empty, private directory (not from `/usr`, which
packages write under), with the switches that stop it reading `AGENTS.md`,
`CLAUDE.md`, `CONTEXT.md` and `opencode.json` from its directory and the ones
above it, `~/.claude/CLAUDE.md` and Claude Code's skills, skills from other
tools' directories and its default plugins (`OPENCODE_DISABLE_PROJECT_CONFIG`,
`OPENCODE_DISABLE_CLAUDE_CODE` and its `_PROMPT` and `_SKILLS` forms,
`OPENCODE_DISABLE_EXTERNAL_SKILLS`, `OPENCODE_DISABLE_DEFAULT_PLUGINS`), and
without updating itself or downloading language servers. For the pacman gate
OpenCode also gets private, empty configuration and cache directories, so your
own OpenCode settings do not shape the review of a root transaction. Neither
reviewer inherits `NODE_OPTIONS`, `BUN_OPTIONS`,
`NODE_TLS_REJECT_UNAUTHORIZED`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT` or
`OPENCODE_PERMISSION`: they load code into the reviewer, switch off its TLS
checks or lift the tool denials, and a review has no use for them. Variables
that people do use, for a proxy, Bedrock or Vertex, are kept, and the report
names the ones that were set (names only): `ANTHROPIC_BASE_URL`,
`ANTHROPIC_BEDROCK_BASE_URL`, `ANTHROPIC_VERTEX_BASE_URL`,
`CLAUDE_CONFIG_DIR`, `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`,
`HTTPS_PROXY`/`https_proxy`, `ALL_PROXY`/`all_proxy`, `NODE_EXTRA_CA_CERTS`
and `SSL_CERT_FILE`.

What stays yours, and so in the hands of anything running as you: for your own
sources, OpenCode's global configuration in `~/.config/opencode` (a provider's
`baseURL`, a global `AGENTS.md`), and for every review the credentials in
OpenCode's data directory, including "wellknown" logins, through which
OpenCode fetches and merges configuration from that server. System-wide
settings cannot be switched off either: Claude Code applies
`/etc/claude-code/managed-settings.json` and `managed-settings.d/*.json`
whatever `--setting-sources` says, and OpenCode merges
`/etc/opencode/opencode.json` (or `.jsonc`) over the configuration Guardian
passes. When such a file exists the report says the reviewer loads it. For the
pacman gate, a file that sets an endpoint or base URL, a key or credential
helper, environment, hooks or plugins (Claude Code), or providers, plugins,
MCP servers, permissions, tools, agents, modes, instructions, commands or
experimental settings (OpenCode), or that Guardian cannot read as plain JSON
(comments, or over 1 MiB), makes the review unavailable with that reason:
Guardian cannot tell an administrator's policy from a file a package left
there.

## How the review scales

Large sources are reviewed in several AI calls (chunks) instead of being
refused. Files are ranked by risk:

1. Build and install entry points go first and are always sent whole:
   `PKGBUILD`, `.install`, `Makefile`, `GNUmakefile`, `CMakeLists.txt`,
   `meson.build`, `build.rs`, `setup.py`, `pyproject.toml`, `package.json`,
   top-level `*.sh`, systemd units, `.desktop` files, Hyprland `exec` config,
   plugin QML, and any file with a local finding.
2. Other code and runtime config follow.
3. Everything else, with documentation last.

Each chunk is its own reviewer run with its own nonce, and every chunk carries
the full file list, so the model knows what else exists. A chunk is judged on
its own files, so a source that needs several is packed to keep together what
belongs together: the files of one directory, and a file with the files it
names, share a chunk where that takes no more chunks than packing by rank
would. Each chunk is also told which local rules matched in the files of the
other chunks (the rule, the file and the line, not the text), and the report
lists the files that name a file sent in another chunk. That is the limit of
it: a payload split over two files that land in different chunks is seen by no
single request, and Guardian does not ask the model to report every call into
another chunk, because an AI finding blocks (under `strict` even a low one
beside a clear verdict) and large honest sources are full of such calls. A file is charged what it takes in the request (a newline or a
quote takes two bytes there, a control or invisible character six and one
outside the basic plane twelve, a few percent more than the file's size for
ordinary code). A file larger than a chunk is split on line boundaries, each
piece repeating the end of the one before; a single line longer than a chunk
is cut the same way, so nothing is hidden by sitting exactly on a cut. The
first chunk runs alone; the rest run three at a time. A run that finds the AI
unavailable (a provider error; not a timeout, and not a reviewer that could
not be started) is retried once after two seconds. A reply that does not echo
the run's nonce is asked for once more straight away (models drop it now and
then). If it still fails, chunks not yet started are not attempted. A source
that needs more than `max_chunks` chunks of `max_input_kib` is not reviewed at
all (`INCOMPLETE`): a partial AI review is never presented as a review of the
whole source. An entry point that does not fit one request is not cut into
pieces: nothing is sent and the review is `INCOMPLETE`, and so it is when the
file list and the local findings alone take more than half a request.

## Review memory

For user-level sources (AUR, themes, plugins and `scan`/`guard`/`sandbox`
targets), Guardian keeps a review memory in
`$XDG_STATE_HOME/omarchy-guardian`, default `~/.local/state/omarchy-guardian`,
mode 0700. Guardian creates it (and any missing parents) only under an
existing directory you own (a symlink counts as its target), so a run under
`sudo -E` leaves nothing owned by root in your home; otherwise the report says
the memory was not used and the review runs in full:

- **Verdict cache.** A chunk already judged `clear` or `suspicious`, with the
  same prompt, model, variant, thinking level and class, is not sent again for
  `cache_days` (default 30). Reports mark such chunks `from cache`. "The same
  prompt" means its text: the key covers the system prompt, the message and
  the whole request with its instructions, so a reworded prompt never reuses
  an old verdict, whatever its version number says.
- **Diff review of upgrades.** A review becomes the approved baseline of that
  source when every chunk was `clear`, there were no gaps, and the decision is
  `CLEAR` (remarks beside a clear verdict do not stand in the way where the
  profile shows them as remarks). The next review of the same source is then sent as follows: changed
  files whole when they are small (up to 48 KiB: what a changed line switches
  on may be anywhere in the file), larger changed files whole too while
  together they fit half a request, and the rest as unified diffs with twenty
  lines of context against the baseline; new files and entry points whole; and
  unchanged files only as names in the file list, except the files a new or
  changed file names, which are sent along while they fit half a request. Any
  unchanged text file counts, whatever it is (a test fixture, a build helper,
  a document), named by its name (`payload.c`, or `helper` for `helper.py`),
  by a path (`build-aux/run`), or by a glob or directory that covers it
  (`tests/*.dat`, `hooks.d/`); a short name without an extension, such as
  `run`, counts only as part of a path. When a named file does not fit, the
  review is done in full if that fits `max_chunks`; if not, it stays an
  upgrade review, and the model and the report are told which named files were
  not sent. If the upgrade does not fit in `max_chunks` with these extras, the
  changes alone are sent. What a change switches on in a file that is neither
  shown nor named this way is not seen in that review: it was reviewed when it
  was approved. Local rules and the dependency audit still read every file.

  A baseline only counts under the prompt (its version and its wording),
  model, variant and thinking level that approved it; after any of them
  changes, the next review is a full one. A baseline also ages: after five
  upgrades approved as diffs, or thirty days, since the source was last
  reviewed in full, the next review is a full one, and so is the first review
  after an update of Guardian from a version that did not keep that count. So
  is the review of a version in which a file Guardian does not read (a binary,
  a link) was added, changed or removed, of a tree with a skipped generated
  directory, and of a version in which a file other than a document was
  removed (or any file, when nothing else changed): what the unchanged text
  runs may no longer be what was approved. When binaries or links differ, the
  AI is told which.

  An image is the exception, so a new wallpaper costs no AI call: the file
  must be named as one (`.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`), not be
  executable, and be one whole image from its first byte to its last by that
  format's own structure (a file that only starts like an image, or has
  anything after it, does not count). It must also be plausibly nothing but a
  picture: only the chunks and segments its format defines, text and comments
  of at most 1 KiB each and 4 KiB together, other metadata of at most 64 KiB,
  a colour profile of at most 1 MiB and an XMP packet of at most 16 KiB, no
  block of text lines in its metadata, and no line anywhere that a shell would
  act on (a shell asked to run a PNG does run it). A line counts by the text
  it starts with, whatever bytes end it: a shell reads past them, or stops at
  a `#`. That last test is a heuristic over the file's bytes: now and then it
  takes a real picture for one, which costs a full review, and it cannot rule
  out every line a shell could run. So the exception does not rest on the
  bytes alone. It holds only away from where files are run: an image in a
  directory that also holds a script (a file with a shebang, the execute bit,
  or a `.sh`, `.bash`, `.zsh`, `.fish`, `.py`, `.pl`, `.rb`, `.lua` or `.js`
  name), or in one whose files a reviewed line runs (`for h in hooks.d/*`,
  `source dir/*`, `run-parts dir`, `find dir -exec`, `cat dir/* | sh`), is a
  file Guardian does not read like any other, and a new or changed one means a
  full review. A wallpaper among wallpapers, or a preview beside configuration
  files, stays the exception. And a reviewed line that runs, sources or reads
  in a file named as an image makes the review incomplete, whatever the image
  holds. Guardian still does not look at what an image shows, and a loop
  written in another language than shell is not followed to its directory, so
  what is left rests on the approved text not running files it was not sent,
  which its review is asked to report.

  A source identical to its baseline is answered from the cache when its first
  review is still cached (yay's second `makepkg` pass); otherwise it is
  reviewed as an upgrade like any other. The `strict` profile turns diff
  review off.

The AUR gate remembers a build by its AUR package name (`aur:<package>` for
the recipe, `aur-src:<package>` for the upstream sources) when the build
directory is a clone of that package, and any other build directory by a key
made from its path. The theme handler remembers a theme by its name. Other
targets are remembered by their class and path. `omarchy-guardian forget ID`
drops that identity's baselines, and for `aur:<pkg>` or `aur-src:<pkg>` also
what the AUR gate remembers of the package (answered questions, binary hashes,
what it extracted). Cached verdicts are kept, so an unchanged rebuild can
still be answered from the cache. The recipe and the upstream sources have
separate baselines: forget both identities to have both reviewed in full.
`omarchy-guardian forget --all` also clears every cached verdict. `config
show` prints the memory's location and size. The memory is kept under
`max_store_mib` (default 256 MiB): expired verdicts go first, then the oldest
baselines.

The pacman gate never uses this memory: every scriptlet gets a fresh, full
review. Because the memory lives in your home directory, malware already
running as your user could plant a cached `clear` verdict. Such malware could
equally edit your shell start-up files, so the user-level gates never defended
against it. Set `cache = "off"` and `diff = "off"` for a class to review it in
full every time.

## Using Claude Code as the reviewer

A model written `claude-code/<model>` runs the review through the Claude Code
CLI (`claude`) instead of OpenCode, with your existing Claude login:

```toml
[agent]
model = "claude-code/claude-sonnet-5-5"
```

(or pick it in `omarchy-guardian tui` or `setup`, which list the Claude Code
models when `claude` is installed and suggest
`claude-code/claude-sonnet-5-5`). Guardian runs `claude --print` with every
built-in tool disabled (`--tools ""`), no MCP servers (`--strict-mcp-config`),
no user, project or local settings, hooks or plugins (`--setting-sources ""`),
no slash commands and no saved session, from an empty private working
directory; the request goes on stdin, and the reply is read as a `stream-json`
transcript. A `tool_use` block in any assistant message, or a permission
denial, counts as a tool attempt and makes the review invalid; the extra turn
the CLI adds to continue a reply its safety classifier interrupted does not.
The reply must echo the nonce like OpenCode's. `thinking` becomes `--effort`
(`minimal` and `low` both as `low`; `default` passes no flag). Claude Code has
no flag that leaves out the administrator's managed settings
(`--setting-sources` covers user, project and local settings only), so those
still apply; see above for what Guardian does about them.

For your own sources `claude` is found on `PATH`. The pacman gate, as with
OpenCode, only accepts a root-owned `/usr/bin/claude` or
`/usr/local/bin/claude`; a Claude Code installed in your home directory is not
used for it, and `pacman-hook --preflight` says so.
