#!/bin/bash
# Prints one hash for the source a package is built from: every file under
# DIR (default: the checkout this script is in) by path and content, except
# what is never part of the source: .git, cargo's and makepkg's output. The
# PKGBUILD installs it as /usr/share/omarchy-guardian/source-id, and
# install.sh compares it with the checkout's, so a checkout that changed
# without a new version number is built again instead of skipped.
#
# Works without git (a release exported by integrations/upgrade.sh has no
# .git). A file that is not part of the package (an editor's settings
# directory) changes the hash too: that only costs a rebuild.
#
#   packaging/source-id.sh [DIR]

set -euo pipefail

root=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
cd "$root"

# Paths are relative and sorted bytewise, so the hash does not depend on
# where the checkout is or on the locale.
find . \( -path ./.git -o -path ./target -o -path ./packaging/arch/src \
    -o -path ./packaging/arch/pkg -o -name '*.pkg.tar.*' \) -prune \
    -o -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 -r sha256sum |
    sha256sum |
    cut -d' ' -f1
