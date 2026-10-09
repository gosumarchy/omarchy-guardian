#!/bin/bash
# The two steps of a release that are done by hand, each as one command.
#
#   packaging/release.sh prepare X.Y.Z [--no-checks]
#       From an up-to-date main: writes X.Y.Z into Cargo.toml, Cargo.lock
#       and packaging/arch/PKGBUILD on a branch release-X.Y.Z, runs the
#       checks a release is held to, commits those three files with the
#       release notes, pushes the branch and opens the pull request.
#       The notes are written first, as packaging/notes/vX.Y.Z.md: the
#       published release shows that file as it is in the tag.
#
#   packaging/release.sh tag X.Y.Z
#       Once that pull request is merged: signs the tag vX.Y.Z on
#       origin/main (your release key asks for its passphrase), checks it
#       with packaging/check-release.sh, and pushes it after a last
#       question. A pushed tag cannot be moved or deleted. The Release
#       workflow then checks the tag again and publishes the release.
set -euo pipefail

die() {
    printf 'release: %s\n' "$*" >&2
    exit 1
}
step() { printf '\n== %s\n' "$*"; }

usage() {
    sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p}' "${BASH_SOURCE[0]}"
    exit "${1-0}"
}

cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")/.."
command=${1-}
version=${2-}
[[ $command == -h || $command == --help ]] && usage
[[ $command == prepare || $command == tag ]] || usage 1
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "the version is written X.Y.Z"
tag=v$version
notes=packaging/notes/$tag.md

current() { sed -n '/^\[package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1; }

# Main as origin has it, with nothing of one's own in the files git tracks.
on_current_main() {
    [[ $(git branch --show-current) == main ]] || die "run this on main"
    git fetch --quiet origin
    [[ $(git rev-parse HEAD) == "$(git rev-parse refs/remotes/origin/main)" ]] ||
        die "main is not what origin/main is (git pull, or push what is missing)"
    [[ -z $(git status --porcelain --untracked-files=no) ]] || die "there are uncommitted changes"
}

prepare() {
    local checks=1 branch=release-$version from
    [[ ${1-} == --no-checks ]] && checks=0
    on_current_main
    from=$(current)
    [[ $from != "$version" && $(printf '%s\n%s\n' "$from" "$version" | sort -V | tail -n 1) == "$version" ]] ||
        die "$version is not newer than $from"
    [[ -s $notes ]] || die "write the release notes first: $notes"
    git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null && die "$tag exists already"

    step "Version $from -> $version on $branch"
    git switch --quiet --create "$branch"
    sed -i "/^\[package\]/,/^\[/s/^version = \"$from\"\$/version = \"$version\"/" Cargo.toml
    sed -i -e "s/^pkgver=.*/pkgver=$version/" -e 's/^pkgrel=.*/pkgrel=1/' packaging/arch/PKGBUILD
    cargo update --quiet --offline --package omarchy-guardian
    [[ $(current) == "$version" ]] || die "Cargo.toml did not take the version"
    [[ $(git status --porcelain --untracked-files=no | sed 's/^...//' | sort | tr '\n' ' ') == \
        "Cargo.lock Cargo.toml packaging/arch/PKGBUILD " ]] ||
        die "more or less than the three version files changed: $(git status --short --untracked-files=no | tr '\n' ' ')"

    local checked='nothing (`--no-checks`)'
    if ((checks)); then
        step "Checks"
        cargo fmt --all -- --check
        cargo clippy --locked --all-targets --all-features -- -D warnings
        cargo test --locked
        bash tests/docs-links.sh
        cargo build --locked --release
        bash tests/e2e/gates-offline.sh
        bash tests/e2e/sweep.sh
        checked='`cargo fmt`, `cargo clippy -D warnings`, `cargo test`, `tests/docs-links.sh`, `tests/e2e/gates-offline.sh`, `tests/e2e/sweep.sh`'
    fi

    step "Pull request"
    git add Cargo.toml Cargo.lock packaging/arch/PKGBUILD "$notes"
    git commit --quiet --message "Release $version"
    git push --quiet --set-upstream origin "$branch"
    gh pr create --title "Release $version" --body "Version $version in \`Cargo.toml\`, \`Cargo.lock\` and \`packaging/arch/PKGBUILD\`, and its release notes in \`$notes\`.

Checked on this branch: $checked."
    printf '\nWhen it is merged: git switch main && git pull && packaging/release.sh tag %s\n' "$version"
}

sign_and_push() {
    on_current_main
    [[ $(current) == "$version" ]] || die "main is at $(current), not $version: is the release pull request merged?"
    git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null && die "$tag exists already"
    git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1 && die "$tag is on origin already"

    step "Signing $tag on $(git rev-parse --short HEAD)"
    git tag --sign "$tag" --message "Omarchy Guardian $version" HEAD
    if ! bash packaging/check-release.sh "$tag"; then
        git tag --delete "$tag" >/dev/null
        die "the tag did not pass and was removed again; nothing was pushed"
    fi

    printf '\nA pushed tag cannot be moved or deleted. Push %s? [y/N] ' "$tag"
    local answer=''
    read -r answer || true
    if [[ $answer != [yY] ]]; then
        git tag --delete "$tag" >/dev/null
        die "not pushed; the tag was removed again"
    fi
    git push origin "refs/tags/$tag"
    printf '\nPushed. The Release workflow checks the tag and publishes the release:\n  gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq ".[0].databaseId")"\n'
}

case $command in
    prepare) prepare "${3-}" ;;
    tag) sign_and_push ;;
esac
