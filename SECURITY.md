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
  granted, without the review the README says it gets;
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

Known limits, stated in the README, are not vulnerabilities by themselves:
compiled programs are not inspected, a clear result is not a guarantee, and
a program already running as your user can change files your user owns.
A report that shows one of these limits is cheaper to close than the README
assumes is still welcome.

## Supported versions

Only the latest release is supported. Upgrade with
`git pull && ./install.sh`.

## Verifying what you install

Releases are annotated git tags (`vX.Y.Z`). `./install.sh` says which commit
and tag it is about to build. Where the installed Guardian carries a list of
release signing keys (`/usr/share/omarchy-guardian/allowed_signers`), the
installer checks that the checkout is a release tag signed by one of them
before building, and asks before going on when it is not.
