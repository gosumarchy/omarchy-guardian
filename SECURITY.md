# Security policy

Omarchy Guardian is a security gate that runs as root inside pacman
transactions. A weakness in it is a weakness in every system that relies on
it, so reports are welcome and handled first.

## Reporting a vulnerability

Please do not open a public issue for a weakness that lets something past a
gate, turns Guardian off, or runs code through it.

Report it privately with GitHub's **Report a vulnerability** button on the
repository's *Security* tab
(<https://github.com/gosumarchy/omarchy-guardian/security/advisories/new>).
Include:

- the Guardian version (`pacman -Q omarchy-guardian`) and the profile in use
  (`omarchy-guardian config show`);
- what an attacker has to control (a package, an AUR recipe, a theme, a
  program already running as the user, another local account);
- the smallest sample or steps that show it, as inert text where possible.

You should get an answer within a week. A fix is released as a new version
and the advisory is published with it, crediting the reporter unless they
ask otherwise.

## What counts

In scope:

- a package, recipe, theme or plugin that gets code to run, or rights
  granted, without the review the documentation says it gets;
- a way for reviewed content to change Guardian's verdict other than by
  being harmless (steering the reviewer, hiding from the local rules,
  poisoning the review memory of another source);
- a way for an unprivileged local account or program to weaken the pacman
  gate, read what the root checks protect, or make the root collector act
  for it;
- Guardian itself running or loading reviewed content before its review is
  done;
- anything that makes the terminal, the saved report or a notification show
  something other than what was reviewed.

Known limits, stated in the README and in full under
[Limitations](docs/limitations.md), are not vulnerabilities by themselves:
compiled programs are not inspected, a clear result is not a guarantee, and
a program already running as your user can change files your user owns.
A report showing that one of these limits is easier to exploit, or cheaper
to close, than the documentation says is still welcome.

## Supported versions

Only the latest release is supported. Upgrade with
`git pull && /usr/lib/omarchy-guardian/upgrade` in your checkout; while the
installed Guardian is older than 0.8.0, and so has no release keys and no
upgrade check, with `git pull && ./install.sh`.

## Verifying what you install

Releases are annotated git tags (`vX.Y.Z`); from 0.8.0 on, the release that
added the key file `packaging/allowed_signers`, they are signed with an SSH
key listed there, and the package installs that list as
`/usr/share/omarchy-guardian/allowed_signers`.

**Upgrades** are verified by the Guardian already installed, with
`/usr/lib/omarchy-guardian/upgrade`, not by anything in the checkout. It
reads the release tag and its objects out of the checkout as data, without
running git in the checkout, so the checkout's configuration, index, hooks
and working tree have no say; copies them into a fresh repository, where
every object is hashed again; verifies the tag's SSH signature there
against the installed keys and requires the signed tag to carry the name it
is stored under; exports exactly the signed tree into an empty directory;
refuses a release older than the installed one unless told otherwise; and
only then builds, with the signed release's own installer. Without
installed keys it builds nothing.

`./install.sh` has a check of its own: that `HEAD` is the commit of a
release tag signed by an installed key and that the working tree is exactly
that commit's tree, file by file, with nothing added. With installed keys
it asks before going on when that is not so, and `--yes` does not answer
the question; without them (a first install) it says what it found and goes
on. This check is part of the checkout it checks. It catches mistakes (the
wrong commit, a changed file); it is no defence against a checkout that was
tampered with, whose installer could have been changed along with it.

What remains trusted, and is therefore in scope when it can be subverted:

- the installed Guardian, its upgrade check and its key list (root-owned,
  and paths the pacman gate protects);
- `git`, `ssh-keygen` and `tar` as installed on the system (git reads the
  checkout's object files, and a flaw in how it parses them is not
  something the upgrade check can make up for);
- the maintainer's release key.

Known limits:

- A first install has no installed keys: it is trust on first use, unless
  you verify the tag by hand against a key you have reason to trust
  ([Verifying a release](docs/install.md#verifying-a-release) shows how).
  The same holds for the upgrade to 0.8.0, the first release that carries
  the key list.
- A package built from a release without the key file installs none, and
  from then on nothing can be verified until one with keys is installed.
- Someone who controls where you pull from can withhold a newer release.
  They cannot forge one, and cannot pass an older one off as an upgrade.
- A new signing key takes effect one release after it is added.

[Cutting a release](docs/development.md#cutting-a-release) says how a
release is signed, and [Upgrading](docs/install.md#upgrading) what the
upgrade check does step by step.
