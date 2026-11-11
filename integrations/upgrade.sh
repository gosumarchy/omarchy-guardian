#!/bin/bash -p
# Upgrades Omarchy Guardian from a checkout without trusting the checkout.
# Installed by the package as /usr/lib/omarchy-guardian/upgrade.
#
# The checkout's own install.sh cannot vouch for the checkout: if the
# checkout was tampered with, so was the script. This one comes from the
# Guardian already installed (root-owned, a protected path of the pacman
# gate), and treats the checkout as data:
#   1. it reads the release tag's object id from the checkout's .git as
#      text and the checkout's objects as files; no git command is ever run
#      with the checkout as its repository, so nothing the checkout
#      configures (.git/config, hooks, its index, core.worktree, replace
#      refs, attributes) is used
#   2. it copies the tag and what the tag names into a fresh repository of
#      its own, where every object is hashed again and checked
#   3. it verifies the tag's SSH signature there, by object id, against the
#      keys the installed Guardian carries
#      (/usr/share/omarchy-guardian/allowed_signers), and requires the
#      signed tag to carry the name it is stored under
#   4. it exports exactly the signed tree into an empty directory: no file
#      of the working tree, no build output
#   5. it refuses a release older than the one installed
#   6. it runs the exported, signed install.sh, which builds and installs
#
# What it relies on: the installed Guardian and its key list, git and
# ssh-keygen from the system, and the release key. What it cannot know: a
# release newer than the newest tag the checkout has.
#
# Run it as your user in the checkout, after `git pull` (or `git fetch
# --tags`). The export and its build live in a private directory under
# ~/.cache/omarchy-guardian/ and are removed when the installer returns.
#
# Usage: /usr/lib/omarchy-guardian/upgrade [options] [checkout [tag]]
#   checkout           the directory with the .git directory (default: .)
#   tag                the release to install (default: the highest vX.Y.Z
#                      tag in the checkout that verifies)
#   --check            verify and export only; build and install nothing
#   --keep             keep the private directory and say where it is
#   --allow-downgrade  install a release older than the installed one
#   --yes, --reinstall, --allow-snapshot-boot
#                      passed on to the release's install.sh
set -euo pipefail

# FUNCNEST=1 would stop the check's function call below, and bash goes on
# after a command it stops; TMOUT would time its `read` out, which counts
# as not clean, but nothing here wants either.
unset TMOUT FUNCNEST

# Only these variables of the caller's reach this script, the tools it
# runs and the installer: the session the installer's own steps need
# (sudo's terminal, the user's systemd and notifications, rustup's
# toolchain, a proxy and certificates for cargo's download), the setup's
# test review (where it is sent, and the login and provider settings
# `is_kept` adds), the snapshot-boot override, and the test suite's three.
# The rest is dropped by starting again under `env -i`: BASH_ENV and
# exported functions would run in every bash the installer starts
# (makepkg is one), TAR_OPTIONS changes what the export holds, GIT_*
# redirects git, and LD_PRELOAD loads into every tool started after the
# restart. The `-p` on this script's first line keeps BASH_ENV and
# functions out of this shell before the check; run it as a command, not
# through `bash`.
#
# This keeps a stray setting from changing what is verified and built. It
# is no defence against a program running as you: one that can set your
# environment can as well wrap this command before it starts (a shell
# function may be named by a path, and LD_PRELOAD loads into this first
# shell), and the build runs your toolchain, which the kept PATH, HOME,
# XDG_CONFIG_HOME, CARGO_HOME and RUSTUP_HOME choose.
KEPT_VARIABLES=(
    HOME USER LOGNAME PATH TERM COLORTERM NO_COLOR TMPDIR
    DISPLAY WAYLAND_DISPLAY XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS
    XDG_CONFIG_HOME XDG_CACHE_HOME XDG_DATA_HOME XDG_STATE_HOME
    CARGO_HOME RUSTUP_HOME
    http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY
    SSL_CERT_FILE SSL_CERT_DIR NODE_EXTRA_CA_CERTS
    CLAUDE_CONFIG_DIR CODEX_HOME OPENCODE_CONFIG OPENCODE_CONFIG_DIR CLOUD_ML_REGION
    OPENAI_BASE_URL OLLAMA_HOST
    OMARCHY_GUARDIAN_ALLOW_SNAPSHOT_BOOT
    GUARDIAN_UPGRADE_TEST_SIGNERS GUARDIAN_UPGRADE_TEST_INSTALLED GUARDIAN_UPGRADE_TEST_AS_ROOT
)
# What bash itself sets in a shell it starts, and the mark of a restart:
# allowed in the environment, never carried over.
SHELL_VARIABLES=(PWD OLDPWD SHLVL _ GUARDIAN_UPGRADE_RESTARTED)

# Whether the caller's variable `name` is carried over: one of
# KEPT_VARIABLES, a locale category, or a login or provider setting of the
# reviewer (`ANTHROPIC_API_KEY`, Bedrock's `AWS_*`, Vertex's `GOOGLE_*`,
# Claude Code's `CLAUDE_CODE_USE_*`), which only the reviewer reads; and its
# `value`, where a locale names no path: gettext builds the path of the
# message catalogs it loads from `LANGUAGE` and the locale (`../..` there
# reaches any directory). `LOCPATH`, which names where locale data is
# loaded from, is not kept at all. A name no shell could have assigned
# (`AWS_a/b`) is not kept either, however it starts.
is_kept() {
    local name=$1 value=$2 kept
    [[ $name =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    if [[ $name =~ ^LC_[A-Z]+$ || $name == LANG || $name == LANGUAGE ]]; then
        [[ $value != */* ]]
        return
    fi
    case $name in
        ANTHROPIC_* | CLAUDE_CODE_USE_* | CLAUDE_CODE_OAUTH_TOKEN | CLAUDE_CODE_SKIP_*_AUTH) return 0 ;;
        AWS_* | GOOGLE_* | VERTEX_* | AZURE_* | *_API_KEY) return 0 ;;
    esac
    for kept in "${KEPT_VARIABLES[@]}"; do
        [[ $name == "$kept" ]] && return 0
    done
    return 1
}

is_shell_variable() {
    local name=$1 shell
    for shell in "${SHELL_VARIABLES[@]}"; do
        [[ $name == "$shell" ]] && return 0
    done
    return 1
}

# Clean only when every entry was read to the end of the list and `env`
# listed it whole: a `read` that fails for any other reason than the end,
# or an `env` that failed (and so listed nothing), is no proof.
only_kept_variables() {
    local entry status name
    while true; do
        IFS= read -r -d '' entry || {
            status=$?
            [[ $status == 1 && -z $entry ]] || return 1
            break
        }
        name=${entry%%=*}
        is_kept "$name" "${entry#*=}" || is_shell_variable "$name" || return 1
    done < <(/usr/bin/env -0)
    wait "$!"
}

# Clean is what the check has to prove: bash goes on after a command it
# stops (a function nested too deep), and `if ! check` would then go on as
# if it had passed.
clean=0
only_kept_variables && clean=1
if ((clean == 0)); then
    # Once: an environment still not clean after the restart (a wrapper
    # that adds variables) stops here instead of restarting for ever.
    if [[ -n ${GUARDIAN_UPGRADE_RESTARTED-} ]]; then
        printf '%s\n' 'upgrade: the environment still holds variables it does not keep' \
            'after starting again with only those; run it from a plain shell' >&2
        exit 1
    fi
    # Only what the caller exported: bash sets some kept names itself.
    mapfile -t names < <(compgen -e)
    kept=(GUARDIAN_UPGRADE_RESTARTED=1)
    for name in "${names[@]}"; do
        is_kept "$name" "${!name}" && kept+=("$name=${!name}")
    done
    exec /usr/bin/env -i "${kept[@]}" /usr/bin/bash -p -- "${BASH_SOURCE[0]}" "$@"
fi
unset clean kept name names GUARDIAN_UPGRADE_RESTARTED

SELF=$(/usr/bin/readlink -f -- "${BASH_SOURCE[0]}")
# install.sh needs the caller's PATH (rustup's cargo); nothing here does.
CALLER_PATH=${PATH-}
CALLER_UMASK=$(umask)
export PATH=/usr/bin
export LC_ALL=C
umask 077

SIGNERS=/usr/share/omarchy-guardian/allowed_signers
PACKAGE=omarchy-guardian
TAG_PATTERN='^v[0-9]+(\.[0-9]+)*(-[0-9]+)?$'
ID_PATTERN='^([0-9a-f]{40}|[0-9a-f]{64})$'

die() {
    printf 'upgrade: %s\n' "$*" >&2
    exit 1
}
say() { printf '%s\n' "$*"; }

# For the test suite, and only for a copy that is not the installed one: a
# script under /usr ignores all three. They let a test name a key file it
# made, the version to take as installed, and let the suite run in a
# container where it is root.
INSTALLED_COPY=1
TEST_INSTALLED_SET=0
TEST_INSTALLED=''
TEST_AS_ROOT=0
if [[ $SELF != /usr/* ]]; then
    INSTALLED_COPY=0
    [[ -n ${GUARDIAN_UPGRADE_TEST_SIGNERS-} ]] && SIGNERS=$GUARDIAN_UPGRADE_TEST_SIGNERS
    if [[ -n ${GUARDIAN_UPGRADE_TEST_INSTALLED+set} ]]; then
        TEST_INSTALLED_SET=1
        TEST_INSTALLED=$GUARDIAN_UPGRADE_TEST_INSTALLED
    fi
    [[ ${GUARDIAN_UPGRADE_TEST_AS_ROOT-} == 1 ]] && TEST_AS_ROOT=1
fi

CHECK_ONLY=0
KEEP=0
ALLOW_DOWNGRADE=0
ALLOW_SNAPSHOT_BOOT=0
installer_args=()
positional=()
while (($#)); do
    case $1 in
        --check) CHECK_ONLY=1 ;;
        --keep) KEEP=1 ;;
        --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
        -y | --yes) installer_args+=(--yes) ;;
        --allow-snapshot-boot) ALLOW_SNAPSHOT_BOOT=1 ;;
        --reinstall) installer_args+=(--reinstall) ;;
        -h | --help)
            /usr/bin/sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p}' "$SELF"
            exit 0
            ;;
        --)
            shift
            positional+=("$@")
            break
            ;;
        -*) die "unknown option $1 (see --help)" ;;
        *) positional+=("$1") ;;
    esac
    shift
done
((${#positional[@]} <= 2)) || die "too many arguments (see --help)"
dir_arg=${positional[0]-.}
tag_arg=${positional[1]-}

###############################################################################
# 1. Who runs this, and with which keys
###############################################################################
if ((EUID == 0 && !TEST_AS_ROOT)); then
    die "run this as your user, not root: nothing here needs root, and the installer asks for sudo when a step does"
fi
for tool in /usr/bin/git /usr/bin/ssh-keygen /usr/bin/tar /usr/bin/vercmp /usr/bin/pacman; do
    [[ -x $tool ]] || die "$tool is needed"
done
if [[ ! -e $SIGNERS && ! -L $SIGNERS ]]; then
    die "this installed Guardian carries no release keys ($SIGNERS), so a release cannot be verified. Nothing was built. See 'Verifying a release' in docs/install.md for checking a tag by hand."
fi
[[ -f $SIGNERS && ! -L $SIGNERS ]] || die "$SIGNERS is not a regular file"
if ((INSTALLED_COPY)); then
    read -r signers_owner signers_mode < <(/usr/bin/stat -c '%u %a' -- "$SIGNERS")
    [[ $signers_owner == 0 ]] || die "$SIGNERS is not owned by root"
    ((!(8#$signers_mode & 022))) || die "$SIGNERS can be written by others than root"
fi

###############################################################################
# 2. The checkout, as data
###############################################################################
DIR=$(/usr/bin/realpath -e -- "$dir_arg") || die "no such directory: $dir_arg"
[[ -d $DIR ]] || die "$DIR is not a directory"
# The path is written into a file git reads line by line.
[[ $DIR != *$'\n'* ]] || die "the checkout's path contains a line break"
SOURCE=$DIR/.git
if [[ -L $SOURCE || (-e $SOURCE && ! -d $SOURCE) ]]; then
    die "$SOURCE is not a directory (a linked worktree or a submodule): run this in the main checkout"
fi
[[ -d $SOURCE ]] || die "$DIR is not the top of a git checkout (no .git directory)"
[[ -d $SOURCE/objects ]] || die "$SOURCE has no objects directory"
if [[ -n $tag_arg && ! $tag_arg =~ $TAG_PATTERN ]]; then
    die "not a release tag name: $tag_arg (expected vX.Y.Z)"
fi

# tag_id <name>: the object id the checkout stores for refs/tags/<name>,
# read as text from the loose ref or from packed-refs. Git is not asked: it
# would read the checkout's configuration to answer. Whatever the text
# says, the id is only a claim until the object behind it has been copied,
# hashed and verified below.
tag_id() {
    local name=$1 loose=$SOURCE/refs/tags/$1 packed=$SOURCE/packed-refs id ref rest
    if [[ -e $loose || -L $loose ]]; then
        [[ -f $loose && ! -L $loose ]] || return 1
        id=$(/usr/bin/head -c 200 -- "$loose" | /usr/bin/tr -d '\0' | /usr/bin/head -n 1)
        [[ $id =~ $ID_PATTERN ]] || return 1
        printf '%s\n' "$id"
        return 0
    fi
    [[ -f $packed && ! -L $packed ]] || return 1
    while read -r id ref rest; do
        if [[ $ref == "refs/tags/$name" && -z $rest && $id =~ $ID_PATTERN ]]; then
            printf '%s\n' "$id"
            return 0
        fi
    done <"$packed"
    return 1
}

# The release tag names the checkout has, highest version first.
tag_names() {
    local path id ref rest
    {
        for path in "$SOURCE"/refs/tags/v*; do
            printf '%s\n' "${path##*/}"
        done
        if [[ -f $SOURCE/packed-refs && ! -L $SOURCE/packed-refs ]]; then
            while read -r id ref rest; do
                [[ $ref == refs/tags/v* ]] && printf '%s\n' "${ref#refs/tags/}"
            done <"$SOURCE/packed-refs"
        fi
    } | /usr/bin/grep -E -- "$TAG_PATTERN" | /usr/bin/sort -u | /usr/bin/sort -r -V || true
}

###############################################################################
# The private directory: the fresh repositories, the export and its build
###############################################################################
CACHE=${XDG_CACHE_HOME:-${HOME:?HOME is not set}/.cache}/omarchy-guardian
/usr/bin/mkdir -p -- "$CACHE"
WORK=$(/usr/bin/mktemp -d -- "$CACHE/upgrade.XXXXXXXXXX")
cleanup() {
    if ((KEEP)); then
        say "Kept: $WORK"
    elif [[ -n $WORK && -d $WORK ]]; then
        /usr/bin/rm -rf -- "$WORK"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/bin/mkdir -- "$WORK/home"

# pinned_git <git directory> <arguments>: git in one of this script's own
# repositories, with an empty environment and nobody's configuration files:
# not the system's, not the user's (HOME is an empty directory), and never
# the checkout's, which is not a repository to any of these commands.
pinned_git() {
    local repo=$1
    shift
    /usr/bin/env -i PATH=/usr/bin HOME="$WORK/home" LC_ALL=C \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 \
        GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0 \
        /usr/bin/git --no-pager --git-dir="$repo" \
        -c core.hooksPath=/dev/null -c core.fsmonitor=false -c gc.auto=0 \
        -c maintenance.auto=false -c core.commitGraph=false -c core.multiPackIndex=false \
        -c pack.useBitmaps=false -c protocol.allow=never \
        "$@"
}

# verify_release <name>: copies the tag <name> out of the checkout and
# verifies it. On success the verified objects are in $REPO and RELEASE_*
# say what was verified; otherwise WHY says what was wrong.
ATTEMPT=0
REPO=''
WHY=''
RELEASE_COMMIT=''
RELEASE_PRINCIPAL=''
RELEASE_KEY=''
verify_release() {
    local name=$1 id stage repo format=sha1 line object='' type='' tagname='' raw
    ATTEMPT=$((ATTEMPT + 1))
    stage=$WORK/stage.$ATTEMPT
    repo=$WORK/repo.$ATTEMPT

    if ! id=$(tag_id "$name"); then
        WHY="the checkout has no tag $name (git fetch --tags)"
        return 1
    fi
    ((${#id} == 64)) && format=sha256

    # A staging repository of our own whose only link to the checkout is
    # objects/info/alternates: a list of directories to look for object
    # files in. That is data: git reads loose objects and packs from there
    # and nothing else of the checkout (no config, no hooks, no refs, no
    # index). The checkout's commit-graph, multi-pack-index and bitmaps,
    # which summarise objects instead of being them, are switched off above.
    pinned_git "$stage" init -q --bare --template= --object-format="$format" -- "$stage" >/dev/null 2>&1 ||
        { WHY='could not create a repository in the private directory' && return 1; }
    /usr/bin/mkdir -p -- "$stage/objects/info"
    printf '%s\n' "$SOURCE/objects" >"$stage/objects/info/alternates"
    if [[ $(pinned_git "$stage" cat-file -t "$id" 2>/dev/null) != tag ]]; then
        WHY="$name is not a signed tag (it is a plain tag, or its object is missing)"
        return 1
    fi
    pinned_git "$stage" update-ref "refs/tags/$name" "$id" 2>/dev/null ||
        { WHY="could not record $name in the private directory" && return 1; }

    # The repository that is verified and exported from has no link to the
    # checkout at all. The tag, its commit and that commit's files are
    # fetched from the staging repository (so the serving side of the fetch
    # runs in our repository with our configuration, not in the checkout),
    # and the receiving side computes every object's id from its content
    # and checks each object and that none is missing. An object file in
    # the checkout that is not what its name says cannot arrive under that
    # name.
    pinned_git "$repo" init -q --bare --template= --object-format="$format" -- "$repo" >/dev/null 2>&1 ||
        { WHY='could not create a repository in the private directory' && return 1; }
    if ! pinned_git "$repo" -c protocol.file.allow=always \
        -c fetch.fsckObjects=true -c transfer.fsckObjects=true \
        fetch -q --no-tags --depth=1 --no-write-fetch-head -- "$stage" "refs/tags/$name:refs/tags/$name" \
        >"$WORK/fetch.log" 2>&1; then
        WHY="the objects of $name could not be copied intact: $(/usr/bin/tail -n 2 -- "$WORK/fetch.log" | /usr/bin/tr '\n' ' ')"
        return 1
    fi
    /usr/bin/rm -rf -- "$stage"
    if [[ $(pinned_git "$repo" rev-parse --verify -q "refs/tags/$name" 2>/dev/null) != "$id" ]] ||
        [[ $(pinned_git "$repo" cat-file -t "$id" 2>/dev/null) != tag ]]; then
        WHY="$name did not arrive as the tag object the checkout names"
        return 1
    fi
    if ! pinned_git "$repo" fsck --strict --no-dangling --no-progress >"$WORK/fsck.log" 2>&1; then
        WHY="the copied objects of $name do not check out: $(/usr/bin/tail -n 2 -- "$WORK/fsck.log" | /usr/bin/tr '\n' ' ')"
        return 1
    fi

    # What the signed tag itself says it is. A genuine signed tag of an old
    # release stored under a newer name must not pass as the newer one.
    while IFS= read -r line; do
        [[ -n $line ]] || break
        case $line in
            'object '*) [[ -n $object ]] || object=${line#object } ;;
            'type '*) [[ -n $type ]] || type=${line#type } ;;
            'tag '*) [[ -n $tagname ]] || tagname=${line#tag } ;;
        esac
    done < <(pinned_git "$repo" cat-file tag "$id")
    if [[ $tagname != "$name" ]]; then
        WHY="the tag stored as $name is really the tag '${tagname//[^A-Za-z0-9._-]/?}'"
        return 1
    fi
    if [[ $type != commit || ! $object =~ $ID_PATTERN ]] ||
        [[ $(pinned_git "$repo" rev-parse --verify -q "$id^{commit}" 2>/dev/null) != "$object" ]]; then
        WHY="$name does not name a commit"
        return 1
    fi

    # The signature: SSH only, checked by /usr/bin/ssh-keygen against the
    # installed keys, by object id. Both git's exit status and
    # ssh-keygen's own words are required.
    if ! pinned_git "$repo" cat-file tag "$id" | /usr/bin/grep -q -- '-----BEGIN SSH SIGNATURE-----'; then
        WHY="$name carries no SSH signature"
        return 1
    fi
    if ! raw=$(pinned_git "$repo" -c gpg.format=ssh -c gpg.ssh.program=/usr/bin/ssh-keygen \
        -c "gpg.ssh.allowedSignersFile=$SIGNERS" -c gpg.ssh.revocationFile=/dev/null \
        -c gpg.program=/usr/bin/false -c gpg.openpgp.program=/usr/bin/false \
        -c gpg.x509.program=/usr/bin/false verify-tag --raw "$id" 2>&1); then
        WHY="$name is not signed by a release key the installed Guardian knows: $(printf '%s' "$raw" | /usr/bin/tail -n 2 | /usr/bin/tr '\n' ' ')"
        return 1
    fi
    if [[ ! $raw =~ (^|$'\n')Good\ \"git\"\ signature\ for\ ([^[:space:]]+)\ with\ [^[:space:]]+\ key\ (SHA256:[A-Za-z0-9+/=]+)($|$'\n') ]]; then
        WHY="the signature check of $name did not name a signer"
        return 1
    fi
    RELEASE_PRINCIPAL=${BASH_REMATCH[2]}
    RELEASE_KEY=${BASH_REMATCH[3]}
    RELEASE_COMMIT=$object
    REPO=$repo
    return 0
}

###############################################################################
# 3. Which release, verified
###############################################################################
TAG=''
if [[ -n $tag_arg ]]; then
    verify_release "$tag_arg" || die "$WHY. Nothing was built."
    TAG=$tag_arg
else
    while IFS= read -r candidate; do
        if verify_release "$candidate"; then
            TAG=$candidate
            break
        fi
        say "Passing over $candidate: $WHY"
    done < <(tag_names)
    [[ -n $TAG ]] || die "no release tag in $DIR is signed by a key the installed Guardian knows (git fetch --tags). Nothing was built."
fi
say "Verified release $TAG"
say "  commit  $RELEASE_COMMIT"
say "  signer  $RELEASE_PRINCIPAL ($RELEASE_KEY)"
say "  keys    $SIGNERS"

###############################################################################
# 4. Exactly the signed tree, in an empty directory
###############################################################################
# Nothing of the checkout's working tree is used: not its files, not what
# its index says about them, not build output left in it. The export has
# no target directory, so cargo builds everything anew.
EXPORT=$WORK/release
/usr/bin/mkdir -- "$EXPORT"
pinned_git "$REPO" archive --format=tar "$RELEASE_COMMIT" |
    /usr/bin/tar -x -f - -C "$EXPORT" --no-same-owner ||
    die "could not export $TAG"
[[ -f $EXPORT/install.sh && -f $EXPORT/packaging/arch/PKGBUILD ]] ||
    die "$TAG has no install.sh or no packaging/arch/PKGBUILD"

###############################################################################
# 5. Not an older release than the installed one
###############################################################################
# A signature says who made a release, not that it is the current one: an
# old release with a known hole is signed too.
new_version=$(/usr/bin/sed -n 's/^pkgver=//p' "$EXPORT/packaging/arch/PKGBUILD" | /usr/bin/head -n 1)-$(/usr/bin/sed -n 's/^pkgrel=//p' "$EXPORT/packaging/arch/PKGBUILD" | /usr/bin/head -n 1)
[[ $new_version =~ ^[0-9][0-9A-Za-z.+_]*-[0-9][0-9.]*$ ]] || die "$TAG has no readable version in its PKGBUILD"
if ((TEST_INSTALLED_SET)); then
    installed=$TEST_INSTALLED
else
    installed=$(/usr/bin/pacman -Q "$PACKAGE" 2>/dev/null | /usr/bin/cut -d' ' -f2 || true)
fi
if [[ -z $installed ]]; then
    say "  version $new_version (not installed yet)"
else
    order=$(/usr/bin/vercmp "$new_version" "$installed")
    say "  version $new_version (installed: $installed)"
    if ((order < 0)); then
        if ((ALLOW_DOWNGRADE)); then
            say "This is OLDER than the installed $installed; going on because of --allow-downgrade."
        else
            die "$TAG ($new_version) is older than the installed $installed. A signed old release can carry a hole a later one closed, so it is not installed. Fetch the newer tags (git fetch --tags), or pass --allow-downgrade if this is what you want. Nothing was built."
        fi
    fi
fi

if ((CHECK_ONLY)); then
    say "Export: $EXPORT"
    say "Checked only (--check): nothing was built or installed."
    exit 0
fi

###############################################################################
# 6. The signed installer
###############################################################################
# The export's install.sh is signed content. It is told what was verified
# so that it does not ask about a directory without .git; a release from
# before it knew the option is started without it, and asks.
if /usr/bin/grep -q -- '--verified-by-installed' "$EXPORT/install.sh"; then
    installer_args+=("--verified-by-installed=$TAG:$RELEASE_COMMIT")
fi
# Likewise a release from before --allow-snapshot-boot would stop on it as
# an unknown option; one that knows it also reads the environment variable.
if ((ALLOW_SNAPSHOT_BOOT)); then
    if /usr/bin/grep -q -- '--allow-snapshot-boot' "$EXPORT/install.sh"; then
        installer_args+=(--allow-snapshot-boot)
    else
        printf 'upgrade: %s does not know --allow-snapshot-boot; installing without it\n' "$TAG" >&2
    fi
fi
status=0
(
    cd -- "$EXPORT"
    umask "$CALLER_UMASK"
    export PATH=$CALLER_PATH
    unset LC_ALL
    exec /usr/bin/bash ./install.sh "${installer_args[@]}"
) || status=$?
exit "$status"
