#!/bin/bash
# Checks a release tag before it is published, with the verifier a user's
# machine runs before it installs one. Run by .github/workflows/release.yml
# on every pushed tag and by packaging/release.sh before a tag is pushed.
#
# It is run from a checkout of main, with the tag fetched. The keys
# (packaging/allowed_signers) and the verifier (integrations/upgrade.sh) are
# the checkout's own, not the tag's: a tag cannot vouch for itself.
#
#   1. the tag is named vX.Y.Z and is an annotated tag
#   2. integrations/upgrade.sh --check accepts it: signed by a listed key,
#      carrying its own name, its tree exported whole. Unlike on a user's
#      machine, the release is not compared with an installed one, the key
#      file need not be root's, and the verifier may run as root (CI)
#   3. Cargo.toml, Cargo.lock and packaging/arch/PKGBUILD in the tag all
#      say X.Y.Z
#   4. the tagged commit is on origin/main
#   5. the tag holds its release notes, packaging/notes/vX.Y.Z.md, as a
#      plain file
#
# Usage: packaging/check-release.sh vX.Y.Z [--no-notes]
#   --no-notes  pass over step 5, for a release from before the notes were
#               kept in the repository
#
# For this script's own tests, GUARDIAN_RELEASE_TEST_SIGNERS names another
# key file than the checkout's. The verifier prints the one it used.
set -euo pipefail

die() {
    printf 'check-release: %s\n' "$*" >&2
    exit 1
}
ok() { printf 'ok   %s\n' "$*"; }

usage='usage: packaging/check-release.sh vX.Y.Z [--no-notes]'
tag=${1-}
notes=1
case ${2-} in
    '') ;;
    --no-notes) notes=0 ;;
    *) die "$usage" ;;
esac
(($# <= 2)) || die "$usage"
[[ $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]] || die "$usage"
version=${BASH_REMATCH[1]}

cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")/.."
[[ -f packaging/allowed_signers && -f integrations/upgrade.sh ]] || die "not a checkout of omarchy-guardian"

[[ $(git cat-file -t "refs/tags/$tag" 2>/dev/null) == tag ]] ||
    die "$tag is not an annotated tag in this checkout (git fetch origin \"+refs/tags/$tag:refs/tags/$tag\")"
commit=$(git rev-parse --verify --quiet "refs/tags/$tag^{commit}") || die "$tag names no commit"
ok "$tag is an annotated tag on ${commit:0:12}"

# The verifier refuses to run as root, which a CI container is.
as_root=()
((EUID == 0)) && as_root=(GUARDIAN_UPGRADE_TEST_AS_ROOT=1)
signers=${GUARDIAN_RELEASE_TEST_SIGNERS:-$PWD/packaging/allowed_signers}
env "${as_root[@]}" GUARDIAN_UPGRADE_TEST_SIGNERS="$signers" GUARDIAN_UPGRADE_TEST_INSTALLED= \
    bash integrations/upgrade.sh --check . "$tag" || die "the upgrade check refused $tag"
ok "the upgrade check accepts $tag"

in_tag() { git show "$commit:$1" 2>/dev/null; }
cargo=$(in_tag Cargo.toml | sed -n '/^\[package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' | head -n 1)
lock=$(in_tag Cargo.lock | sed -n '/^name = "omarchy-guardian"$/{n;s/^version = "\(.*\)"$/\1/p}' | head -n 1)
pkgver=$(in_tag packaging/arch/PKGBUILD | sed -n 's/^pkgver=//p' | head -n 1)
[[ $cargo == "$version" ]] || die "Cargo.toml in $tag says '$cargo', not $version"
[[ $lock == "$version" ]] || die "Cargo.lock in $tag says '$lock', not $version"
[[ $pkgver == "$version" ]] || die "packaging/arch/PKGBUILD in $tag says '$pkgver', not $version"
ok "Cargo.toml, Cargo.lock and the PKGBUILD say $version"

git rev-parse --verify --quiet refs/remotes/origin/main >/dev/null || die "origin/main is not fetched"
git merge-base --is-ancestor "$commit" refs/remotes/origin/main ||
    die "the commit of $tag is not on origin/main"
ok "the tagged commit is on origin/main"

if ((notes)); then
    # A link or a directory of that name would be read as whatever it
    # points to where the notes are published.
    [[ $(git ls-tree "$commit" -- "packaging/notes/$tag.md" | cut -f 1) == 100644\ blob\ * ]] ||
        die "$tag has no release notes as a plain file (packaging/notes/$tag.md)"
    [[ -n $(in_tag "packaging/notes/$tag.md") ]] || die "the release notes in $tag are empty"
    ok "release notes are in the tag"
fi
printf '%s is ready to publish.\n' "$tag"
