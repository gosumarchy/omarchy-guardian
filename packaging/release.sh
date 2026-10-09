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
#       If a step fails before the commit, the branch is taken back and
#       main is as it was.
#
#   packaging/release.sh tag X.Y.Z
#       Once that pull request is merged: signs the tag vX.Y.Z on the
#       commit of origin/main that brought the version in (your release key
#       asks for its passphrase), checks it with
#       packaging/check-release.sh, and pushes it after a last question.
#       A pushed tag cannot be moved or deleted; one that is not pushed is
#       removed again. The Release workflow then checks the tag once more
#       and publishes the release.
#
# Both take `origin` to be the repository releases are made in.
set -euo pipefail

SELF=$(readlink -f -- "${BASH_SOURCE[0]}")

die() {
    printf 'release: %s\n' "$*" >&2
    exit 1
}
step() { printf '\n== %s\n' "$*"; }

usage() {
    sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p}' "$SELF"
    exit "${1-0}"
}

cd -- "$(dirname -- "$SELF")/.."
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

# How far `prepare` got, for what to say or undo when it stops.
STAGE=''

prepare_stopped() {
    local status=$? branch=release-$version
    trap - EXIT
    ((status == 0)) && return
    case $STAGE in
        branch)
            # Only what this run made: the tree was clean when it began.
            git checkout --quiet -- Cargo.toml Cargo.lock packaging/arch/PKGBUILD
            git switch --quiet main
            git branch --quiet -D "$branch"
            printf 'release: stopped; the branch %s was taken back and main is as it was\n' "$branch" >&2
            ;;
        committed)
            printf 'release: stopped after the commit, on the branch %s. To go on from here:\n  git push --set-upstream origin %s && gh pr create --title "Release %s"\nTo start over: git switch main && git branch -D %s (the notes are in that commit: copy %s out first)\n' \
                "$branch" "$branch" "$version" "$branch" "$notes" >&2
            ;;
        pushed)
            printf 'release: the branch %s is pushed and has no pull request yet. Open it from that branch:\n  gh pr create --title "Release %s"\n' \
                "$branch" "$version" >&2
            ;;
    esac
    exit "$status"
}

prepare() {
    local checks=1 branch=release-$version from
    case ${1-} in
        '') ;;
        --no-checks) checks=0 ;;
        *) usage 1 ;;
    esac
    on_current_main
    from=$(current)
    [[ $from != "$version" && $(printf '%s\n%s\n' "$from" "$version" | sort -V | tail -n 1) == "$version" ]] ||
        die "$version is not newer than $from"
    [[ -f $notes && ! -L $notes && -s $notes ]] || die "write the release notes first: $notes"
    git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null && die "$tag exists already"
    git rev-parse --verify --quiet "refs/heads/$branch" >/dev/null && die "the branch $branch exists already"

    step "Version $from -> $version on $branch"
    trap prepare_stopped EXIT
    git switch --quiet --create "$branch"
    STAGE=branch
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
        checked='`cargo fmt`, `cargo clippy -D warnings`, `cargo test`, `tests/docs-links.sh`, a release build, `tests/e2e/gates-offline.sh`, `tests/e2e/sweep.sh`'
    fi

    step "Pull request"
    git add Cargo.toml Cargo.lock packaging/arch/PKGBUILD "$notes"
    git commit --quiet --message "Release $version"
    STAGE=committed
    git push --quiet --set-upstream origin "$branch"
    STAGE=pushed
    gh pr create --title "Release $version" --body "Version $version in \`Cargo.toml\`, \`Cargo.lock\` and \`packaging/arch/PKGBUILD\`, and its release notes in \`$notes\`.

Checked on this branch: $checked."
    STAGE=done
    printf '\nWhen it is merged: git switch main && git pull && packaging/release.sh tag %s\n' "$version"
}

# Set once the tag is on origin: until then a local tag is this run's to
# remove, whatever stops it.
PUSHED=0

tag_stopped() {
    local status=$?
    trap - EXIT
    if ((!PUSHED)) && git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
        git tag --delete "$tag" >/dev/null
        printf 'release: %s was not pushed and was removed again\n' "$tag" >&2
    fi
    exit "$status"
}

sign_and_push() {
    (($# == 0)) || usage 1
    on_current_main
    [[ $(current) == "$version" ]] || die "main is at $(current), not $version: is the release pull request merged?"
    git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null && die "$tag exists already"
    git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1 && die "$tag is on origin already"

    # The commit that brought the version in, not whatever came after it.
    local release later
    release=$(git log -1 --format=%H -S"version = \"$version\"" -- Cargo.toml)
    [[ -n $release ]] || die "no commit on main brings version $version into Cargo.toml"
    later=$(git rev-list --count "$release..HEAD")

    step "Signing $tag on $(git log -1 --format='%h %s' "$release")"
    ((later == 0)) || printf '%s later commit(s) on main are not part of %s:\n%s\n' \
        "$later" "$tag" "$(git log --format='  %h %s' "$release..HEAD")"
    trap tag_stopped EXIT
    git tag --sign "$tag" --message "Omarchy Guardian $version" "$release"
    bash packaging/check-release.sh "$tag" || die "the tag did not pass"

    printf '\nA pushed tag cannot be moved or deleted. Push %s? [y/N] ' "$tag"
    local answer=''
    read -r answer || true
    [[ $answer == [yY] || $answer == [yY][eE][sS] ]] || die "not pushed"
    git push origin "refs/tags/$tag"
    PUSHED=1
    printf '\nPushed. The Release workflow checks the tag and publishes the release; see it with:\n  gh run list --workflow release.yml --limit 3\n'
}

case $command in
    prepare) prepare "${@:3}" ;;
    tag) sign_and_push "${@:3}" ;;
esac
