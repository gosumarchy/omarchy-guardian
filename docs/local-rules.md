# Local rules

The checks Guardian runs on the machine itself, without the AI: the pattern
rules for known-bad commands, the check of network destinations, and the
dependency audit. These rules read text, not meaning; what they leave to the
AI review is said below, and the AI review itself is described under
[Review](review.md).

## Contents

- [What they look for](#what-they-look-for)
- [What they pass over](#what-they-pass-over)
- [Across lines and files](#across-lines-and-files)
- [Checks that read every file](#checks-that-read-every-file)
- [Network destinations](#network-destinations)
- [Dependencies](#dependencies)

## What they look for

The local rules run on every text file except prose (`*.md`, `*.rst`,
`README`, licence and legal texts such as `LICENSE.txt`, `COPYING.LESSER`,
`terms.html` or anything under `LICENSES/`, PKGBUILD `*.changelog` files,
...): download-to-shell pipelines, encoded command execution, credential file
access, destructive commands (a recursive `rm` of `/` or `$HOME` itself,
`mkfs`, raw-disk writes), persistence, shell execution, privilege escalation,
disabled TLS verification (`curl -k`, `git http.sslVerify false`,
`--no-check-certificate`, an unverified SSL context, ...) and likely
credential exfiltration.

Also reverse and bind shells (a shell wired to a socket, in a shell one-liner
or built in Python, Perl, PHP, Ruby or awk), cryptocurrency miners and mining
pools, turning off a protection of the system (a firewall, a security service,
SELinux, or one of Guardian's own gates), and erasing shell history or system
logs.

Download-to-shell also covers a fetch piped into another interpreter (`|
python`, `| perl`, `| node`, ...), behind a wrapper (`| timeout 5 sh`, `|
xargs sh -c`) or grouped (`| { sh; }`), a fetch run from a substitution or a
here-string (`eval "$(curl ...)"`, `bash <<< "$(curl ...)"`), other fetchers
(`http`/`https` with an address, `fetch`, `lwp-download`, `nc`, `scp`/`rsync`,
a Python one-liner that reads a URL), and a value held in a variable from a
fetch and later run (`x=$(curl ...)` … `eval "$x"`).

Encoded command execution covers the same shapes for a decoder — `base32`,
`basenc`, `xxd -r` in any flag order, `openssl enc -d`, `rev`, a `tr` or a
`gunzip`/`xz -d`/`zstd -d` of a literal, a `printf '\xNN'` of four or more
escapes — and a decode run in a language (`exec(b64decode(...))`,
`eval(atob(...))`, `new Function(atob(...))`, Lua `load(string.char(...))`,
PowerShell `IEX`/`-enc`), including a decode saved to a variable and then run,
or saved to a file and then run.

A separate **remote-code-install** finding (medium) marks a package manager
told to install and so run code from an address rather than from this source:
`pip install` of a URL or `git+` repository, `npm install` of a
URL/tarball/git or `npx` of an unpinned remote package, `go install …@latest`,
`cargo install --git`; an ordinary `pip install -r requirements.txt`, `npm ci`
with a lockfile or `go build` stays quiet.

Persistence also covers an auto-run directive (a `.desktop` `Exec=`, a systemd
`ExecStart=`, a waybar `on-click`, a Hyprland `exec-once`/`bind … exec`, a
cron line, a udev `RUN+=`) whose command lives where no installed program does
(`/tmp`, `/dev/shm`, `~/.cache`, a hidden dot-file in `$HOME`) — a command in
`/usr/bin`, `~/.local/bin` or beside its own config stays quiet; a start-up
file a script writes (`~/.zshenv`, `~/.config/fish/conf.d`,
`~/.config/hypr/*.conf`, a `~/.local/bin/` wrapper named for
`sudo`/`ssh`/`git`/...); and a command that keeps something running (`loginctl
enable-linger`, `systemd-run --user --on-calendar`, `at`, `chattr +i`, `git
config --global core.hooksPath` or `credential.helper`, a `sudo`/`ssh` alias,
`export LD_PRELOAD=`, a `PATH` rooted in a temp directory, `useradd -o -u 0`).

Likely credential exfiltration also covers a credential store or home file
given to an upload flag (`curl -T`/`-F @`/`--data-binary @`, `wget
--post-file=`), an archive of a home path piped to a sender, the environment
or machine identity (`env`, `id`, `$(hostname)`) put into a request, DNS
exfiltration (`dig "$(...).host"`), and the clipboard read into a sender; and
a credential store (`.gnupg`, `.ssh`, a browser profile, `.password-store`,
`*.kdbx`, shell history) handed to an archiver or copier (`tar`, `cp`, `scp`,
`base64`, ...) is a credential-file finding.

Destructive commands also cover `rm -rf "$VAR"/*` where `VAR` is set nowhere
in the file or only from a command substitution and nothing guards it (no `set
-u`, no `${VAR:?}`, and not a build directory such as `$pkgdir`/`$srcdir` or a
`mktemp` path), a redirection onto a whole block device, and `parted mklabel`.

## What they pass over

Identifier patterns respect word boundaries, so `retrieval(` and
`model.eval()` do not match `eval(`. Making a Chromium-family sandbox helper
setuid root (`chmod 4755` or `chown root` of `chrome-sandbox`,
`msedge-sandbox`, `opera_sandbox`, ...), which every Chromium and Electron
package does, is not a privilege-escalation finding. A persistence path a
PKGBUILD writes into its own package (`"$pkgdir"/etc/profile.d/...`, without
`..`) is a package file, not persistence. A `mkfs.*` program that is only
installed, copied or linked is not run, so it is not a destructive command.

Comments are skipped (shell and other `#` languages, `//` and `/* */` in
C-like languages, Lua `--`, and comment lines a patch adds to a file of one of
those languages). Lines a patch removes are skipped by the same checks as
printed text below, since `patch -R` would apply them.

In shell scripts, text that is only printed (`echo` and `printf` arguments,
`cat <<EOF` bodies, when nothing pipes, redirects or substitutes them) is
skipped by the persistence, privilege, credential-file, TLS and network
checks, so install notes like `echo "run: sudo systemctl enable foo"` are not
findings; download-to-shell, encoded execution, destructive commands and shell
execution still match printed text. Nothing printed is skipped in a script
that redefines `echo`, `printf` or `cat`, enables aliases, pipes anything into
an interpreter (`f | sh`, `| sudo bash`, `| xargs`), or redirects its own
output with `exec` or a process substitution, sends what a loop, a block or
one of its own functions prints to a file (by a redirection, `tee` or `dd`),
or runs a command's output (`eval "$(…)"`, `source <(…)`), since its messages
may then run.

## Across lines and files

A command continued over several lines (a trailing backslash, pipe or `&&`, or
a pipe opening the next line) is also judged as the one line a shell reads,
and a download saved to a file that the same file later runs or sources counts
as download-and-run, also when one file downloads and another runs what it
saved. A fetcher or a shell kept in a variable (`F=curl` … `$F … | $S`) is
read as what it is.

These rules read text, not meaning: a command assembled any other way is left
to the AI review.

A file a reviewed script runs or reads in (`sh ./data/x.png`, `. ./lib`,
`python3 tool.py`, `lua x`, `node x`, a make `include`, a `package.json`
`"scripts"` command, a `sh -c "$(cat x)"`, a `. "$(dirname "$0")/x"` sibling,
or an archive read in with `tar xf`/`unzip`) that Guardian could only hash
makes the review incomplete: it runs, and nobody read it. A prose file a
reviewed line runs (`sh ./README`) is checked by the command rules after all,
even though prose is otherwise exempt.

## Checks that read every file

Two further checks read **every** text file, prose included: text addressed to
a reviewer or an AI model that tells it what to conclude (an injected "ignore
previous instructions", a made-up verdict, a chat-template control token),
reported with an excerpt so a human can judge, while ordinary writing about AI
tools stays quiet; and hidden or reordering characters — bidirectional
controls that reorder text (the Trojan Source technique), invisible Unicode
tag characters, and zero-width characters inside a name, command or path —
which deceive the human and the AI reader without changing what a program does
(writing systems that need these characters, such as right-to-left text and
translation files, stay quiet).

Prose, comments and messages are still sent to the AI review. Of an AUR
build's upstream code, which the AI judges, these local checks keep two
findings: tag characters and reordering controls, which no source code needs.

## Network destinations

Literal HTTP(S) hosts in code and runtime config, flagging cleartext HTTP and
hard-coded IP addresses. A host is also flagged when it is one commonly used
to deliver or receive stolen data (a paste site, a chat webhook such as a
Discord or Slack webhook path, a tunnel or request catcher, dynamic DNS, a
`.onion` address or a link shortener), or when its name is made to read as
another — a label mixing alphabets or written only in look-alikes of Latin
letters, judged the same in its punycode (`xn--`) spelling (a name wholly in
one other script is just a name; an `xn--` label that does not decode is
flagged), or a name that begins with a well-known code host's but belongs to
another domain (`github.com.example.test`). A PKGBUILD's `url=` homepage
(never fetched) and `source=` entries (fetched and checked by makepkg), XML
namespace, DTD and schema identifiers are not destinations; a recipe's
homepage and sources are still checked for a host that reads as another. URL
paths, queries and credentials are never printed: the host reputation is
judged from the path internally, without recording it.

## Dependencies

`Cargo.lock`, npm lockfiles, `poetry.lock`, `go.sum` and exactly pinned
`requirements*.txt` are checked with the public OSV API (only package names
and versions are sent). Advisory severities and summaries are fetched per
advisory; ones OSV does not rate are shown as `UNRATED`. Any advisory blocks a
gate. Unsupported lockfiles, manifests with dependencies but no lockfile (or
one that lists no package at all), or an unavailable OSV API make the review
incomplete.
