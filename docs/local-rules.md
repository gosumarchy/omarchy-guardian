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
- [Rule ids](#rule-ids)

## What they look for

The local rules run on every text file except prose (`*.md`, `*.rst`,
`README`, licence and legal texts such as `LICENSE.txt`, `COPYING.LESSER`,
`terms.html` or anything under `LICENSES/`, PKGBUILD `*.changelog` files,
...): download-to-shell pipelines (`download-and-execute`), encoded command
execution (`encoded-command-execution`), credential file access
(`credential-file-access`), destructive commands
(`destructive-system-operation`: a recursive `rm` of `/` or `$HOME` itself,
`mkfs`, raw-disk writes), persistence (`persistence-modification`), shell
execution (`shell-command-execution`), privilege escalation
(`privilege-escalation`), disabled TLS verification
(`disabled-tls-verification`: `curl -k`, `git http.sslVerify false`,
`--no-check-certificate`, an unverified SSL context, ...) and likely
credential exfiltration (`credential-exfiltration`).

Also reverse and bind shells (`remote-shell`: a shell wired to a socket, in a
shell one-liner or built in Python, Perl, PHP, Ruby or awk), cryptocurrency
miners and mining pools (`crypto-miner`), turning off a protection of the
system (`protection-disabled`: a firewall, a security service, SELinux, or one
of Guardian's own gates), and erasing shell history or system logs
(`trace-removal`). A git configuration in the tree that names a command git
runs is a `git-config-command` finding (see
[Review](review.md#what-is-read-and-what-makes-a-review-incomplete)).

Each finding carries a rule id and a severity. The severity only sets the
headline (`HIGH RISK` with a high finding, `REVIEW REQUIRED` otherwise);
whether a finding blocks or warns follows the class's `on_findings`. The ids
and severities are listed [at the end of this page](#rule-ids).

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

A separate `remote-code-install` finding (medium) marks a package manager
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

A `/*` at the start of a line opens a comment only where code is read: strings
are followed, so a `/*` inside a template string or another string that runs
over lines hides nothing. Where Guardian cannot tell what is being read (a
regular expression or JSX that may hold a quote, a raw or triple-quoted
string, a line spliced with `\` in C, a `#if` in C#, a `\u` escape in Java), no
`/* */` is skipped from there to the end of the file. That only ever shows the
rules more.

In shell scripts, text that is only printed (`echo` and `printf` arguments,
`cat <<EOF` bodies, when nothing pipes, redirects or substitutes them) is
skipped by the persistence, privilege, credential-file, TLS,
network-destination, protection-disabled, trace-removal and
remote-code-install checks, so install notes like `echo "run: sudo systemctl
enable foo"` are not findings; download-to-shell, encoded execution,
destructive commands, shell execution, credential exfiltration, remote shells
and miners still match printed text. Nothing printed is skipped in a script
that does any of these: redefines `echo`, `printf` or `cat`; enables aliases;
pipes anything into an interpreter (`f | sh`, `| sudo bash`, `| xargs`);
redirects its own output with `exec` or a process substitution; sends what a
loop, a block or one of its own functions prints to a file (by a redirection,
`tee` or `dd`); or runs a command's output (`eval "$(…)"`, `source <(…)`). Its
messages may then run.

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
even though prose is otherwise exempt. This follows a file named plainly on
the line; a path built from a variable is not followed. The first 512 prose
files of a tree are kept for it, and a reviewed line that runs one past them
makes the review incomplete.

## Checks that read every file

Two further checks read **every** text file, prose included: text addressed to
a reviewer or an AI model that tells it what to conclude
(`text-addressed-to-reviewer`: an injected "ignore previous instructions", a
made-up verdict, a chat-template control token), reported with an excerpt so a
human can judge, while ordinary writing about AI tools stays quiet; and hidden
or reordering characters — bidirectional controls that reorder text
(`reordered-text`, the Trojan Source technique), invisible Unicode tag
characters (`invisible-text`), and zero-width characters inside a name,
command or path (`hidden-character`) — which deceive the human and the AI
reader without changing what a program does (writing systems that need these
characters, such as right-to-left text and translation files, stay quiet).

Prose, comments and messages are still sent to the AI review. Of an AUR
build's upstream code, which the AI judges, these local checks keep two
findings: tag characters and reordering controls, which no source code needs.

## Network destinations

Guardian lists the literal HTTP(S) hosts in code and runtime configuration,
and flags cleartext HTTP (`cleartext-network-request`) and hard-coded IP
addresses (`direct-ip-network-request`). A host is also flagged when it is one
commonly used to deliver or receive stolen data (`data-drop-host`: a paste
site, a chat webhook such as a Discord or Slack webhook path, a tunnel or
request catcher, dynamic DNS, a `.onion` address or a link shortener), or when
its name is made to read as another (`lookalike-host`) — a label mixing
alphabets or written only in look-alikes of Latin letters, judged the same in
its punycode (`xn--`) spelling (a name wholly in one other script is just a
name; an `xn--` label that does not decode is flagged), or a name that begins
with a well-known code host's but belongs to another domain
(`github.com.example.test`). A PKGBUILD's `url=` homepage (never fetched) and
`source=` entries (fetched and checked by makepkg), XML namespace, DTD and
schema identifiers are not destinations; a recipe's homepage and sources are
still checked for a host that reads as another.

The Network list of a report shows each destination's scheme and host, never
its path, query or login; the host's reputation is judged from the path
internally, without recording it. A finding's excerpt is the line as it is
written, with the login of a URL taken out where it is plain characters
(`http://user:password@host/path` is shown as `http://***@host/path`; a login
holding anything a shell would act on is left as written, so that nothing that
could be code is hidden). A path or a query on that line is shown there and
kept in a saved report.

## Dependencies

`Cargo.lock`, npm lockfiles (`package-lock.json`, `npm-shrinkwrap.json`),
`poetry.lock`, `go.sum` and exactly pinned `requirements*.txt` are checked
with the public OSV API (only package names and versions are sent). Severities
and summaries are fetched for up to 50 advisories; ones OSV does not rate, or
past that number, are shown as `UNRATED`. An advisory counts as a finding and
follows the class's `on_findings`: it blocks wherever that is `block`, which
in the stock profiles is every class but `official` under `standard` and
`local-only`. Unsupported lockfiles, manifests with dependencies but no
lockfile (or one that lists no package at all), or an unavailable OSV API make
the review incomplete. Unsupported are `yarn.lock`, `pnpm-lock.yaml`,
`Pipfile.lock`, `Gemfile.lock` and `composer.lock`. The audit runs under every
profile, `local-only` included: package names and versions go to OSV even
where no source goes to an AI. More than 20,000 locked packages are not
audited, and the review is incomplete.

## Rule ids

The rules a source review can report, as a report and the audit trail name
them. The rule ids the system sweep adds are listed under [System
sweep](system-sweep.md).

| Rule id | Severity | What it reports |
| --- | --- | --- |
| `download-and-execute` | high | Fetches code from the network and runs it without it being reviewed: piped into a shell or an interpreter, run from a substitution, or saved and then run. |
| `encoded-command-execution` | high | Encoded or dynamically evaluated data appears to be executed as a command. |
| `credential-file-access` | medium | References a commonly sensitive credential or private-key file; inspect how it is used. |
| `destructive-system-operation` | high | Contains a command associated with destructive disk or filesystem changes. |
| `persistence-modification` | medium | May install persistence: writes a startup, scheduled-task or SSH authorization file, runs a command on its own from a temporary or cache directory, or arranges for something to keep running. |
| `shell-command-execution` | medium | Starts a shell or dynamically evaluates a command; review how input is constructed. |
| `privilege-escalation` | medium | Requests elevated privileges or changes privilege-related system configuration. |
| `credential-exfiltration` | high | Combines access to sensitive data with an outbound network request. |
| `cleartext-network-request` | medium | Sends a network request over unencrypted HTTP. |
| `direct-ip-network-request` | medium | Sends a request to a hard-coded IP address instead of a named host. |
| `disabled-tls-verification` | medium | Disables TLS certificate verification for network requests. |
| `git-config-command` | medium | A git config in the tree names a command git runs, or another address for git to fetch from, on later commands here (status, describe, diff, fetch). |
| `text-addressed-to-reviewer` | high | Text addressed to a reviewer or an AI model, telling it what to conclude; software has no reason to carry it. |
| `reordered-text` | high | Holds bidirectional control characters: the text is shown in another order than it is read by a compiler, a shell or the AI review. |
| `invisible-text` | high | Holds Unicode tag characters: text no person sees, which an AI model reads as instructions. |
| `hidden-character` | medium | An invisible character sits inside a name, a command or a path: it is not the name it reads as, to a person or to the AI review. |
| `lookalike-host` | medium | A host name mixes alphabets, in letters or in the punycode that spells them, or begins with a well-known host's name but belongs to another domain, so it can read as another name than the one requested. |
| `data-drop-host` | medium | Sends to or fetches from a host commonly used to deliver or receive stolen data (a paste site, a chat webhook, a tunnel, a link shortener). |
| `remote-shell` | high | A shell is connected to the network, so someone elsewhere types the commands (a reverse or bind shell): in code that sets one up, or in a running shell or interpreter with a network socket for its input and output. |
| `crypto-miner` | high | Names a cryptocurrency miner, a mining pool or a mining protocol. |
| `protection-disabled` | high | Turns off a protection of this system: a firewall, a security service, or Guardian's own gates. |
| `trace-removal` | medium | Erases shell history or system logs, which is how traces of other commands are removed. |
| `remote-code-install` | medium | Installs and runs code from an address, not from this source: a package manager is given a URL or a repository, or told to fetch and run a package at whatever its newest version is. |
