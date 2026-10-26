#!/bin/bash
# Prints one hash for the source a package is built from: each file of DIR
# (default: the checkout this script is in) by path and content, and each
# symbolic link by path and target. install.sh takes it before the build
# and the PKGBUILD installs it as /usr/share/omarchy-guardian/source-id, so
# a checkout that changed without a new version number is built again
# instead of skipped.
#
# In a git checkout the files are the ones git tracks or would track
# (`git ls-files --cached --others --exclude-standard`): .gitignore keeps
# build output out, and another repository inside it (an agent's worktree)
# is not read. Without git (a release exported by integrations/upgrade.sh)
# every file is read except cargo's and makepkg's output.
#
#   packaging/source-id.sh [DIR]

set -euo pipefail

root=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
cd "$root"

list() {
    if [[ -e .git ]] && command -v git >/dev/null &&
        [[ $(git rev-parse --show-toplevel 2>/dev/null) == "$(pwd -P)" ]]; then
        git ls-files -z --cached --others --exclude-standard
    else
        find . \( -path ./.git -o -path ./target -o -path ./packaging/arch/src \
            -o -path ./packaging/arch/pkg -o -path './packaging/arch/*.pkg.tar.*' \) -prune \
            -o \( -type f -o -type l \) -print0 | sed -z 's|^\./||'
    fi
}

files=()
links=()
while IFS= read -r -d '' path; do
    if [[ -L $path ]]; then
        links+=("$path")
    elif [[ -f $path ]]; then
        files+=("$path")
    fi
    # Anything else is a directory git lists for a repository inside this
    # one, or a tracked file deleted from disk: neither is built from.
done < <(list | LC_ALL=C sort -z -u)

# Paths are relative and sorted bytewise, so the hash does not depend on
# where the checkout is or on the locale. A file that cannot be read fails
# the whole hash rather than leaving it out.
{
    if ((${#files[@]})); then
        printf '%s\0' "${files[@]}" | xargs -0 sha256sum --
    fi
    for link in "${links[@]}"; do
        printf 'link %s -> %s\n' "$link" "$(readlink -- "$link")"
    done
} | sha256sum | cut -d' ' -f1
