#!/bin/bash
# Installs or upgrades Omarchy Guardian from this checkout and turns its
# protection on:
#   1. checks for a Rust toolchain (rustup's or Arch's)
#   2. builds the Arch package from this checkout
#   3. installs it with pacman, by absolute path so any installed Guardian
#      pacman hook can find the archive
#   4. makes sure there is an AI reviewer (Claude Code, or OpenCode where no
#      repository has the claude-code package)
#   5. runs the guided setup on a first install
#   6. turns every gate on (`omarchy-guardian protect`), showing each step
#   7. tests the reviewer with a malicious and a harmless sample
#
# Run it as your user from anywhere; sudo is asked for when a step needs it.
# Safe to run again: steps that are already done are skipped.
#
# To upgrade an installed Guardian that carries release keys, run
# /usr/lib/omarchy-guardian/upgrade in the checkout instead: it verifies the
# release without relying on anything in the checkout, this script included,
# and then starts the verified release's copy of this script.
#
# Usage: ./install.sh [--yes] [--reinstall]
#   --yes        answer yes to the installer's own questions and to pacman
#                (the guided setup still asks its questions)
#   --reinstall  rebuild and reinstall even when this version is installed
#   --verified-by-installed=<tag>:<commit>
#                given by /usr/lib/omarchy-guardian/upgrade to the export it
#                made of a release it verified; refused in a git checkout
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd -P)
PKG_DIR=$ROOT/packaging/arch
YES=0
REINSTALL=0
VERIFIED=''

for arg; do
    case $arg in
        -y | --yes) YES=1 ;;
        --reinstall) REINSTALL=1 ;;
        --verified-by-installed=*)
            VERIFIED=${arg#*=}
            if [[ ! $VERIFIED =~ ^v[0-9]+(\.[0-9]+)*(-[0-9]+)?:([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
                printf 'install.sh: --verified-by-installed takes <tag>:<commit>\n' >&2
                exit 2
            fi
            ;;
        -h | --help)
            sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p}' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            printf 'install.sh: unknown option %s (see --help)\n' "$arg" >&2
            exit 2
            ;;
    esac
done

if [[ -t 1 ]]; then
    BOLD=$'\e[1m' BLUE=$'\e[34m' GREEN=$'\e[32m' YELLOW=$'\e[33m' RED=$'\e[31m' RESET=$'\e[0m'
else
    BOLD='' BLUE='' GREEN='' YELLOW='' RED='' RESET=''
fi

step() { printf '\n%s==>%s %s%s%s\n' "$BLUE" "$RESET" "$BOLD" "$*" "$RESET"; }
ok() { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
note() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$*"; }
fail() {
    printf '\n%s✗ %s%s\n' "$RED" "$*" "$RESET" >&2
    exit 1
}

# ask <question>: yes by default; --yes answers it.
ask() {
    ((YES)) && return 0
    local answer
    if ! read -r -p "  $1 [Y/n] " answer </dev/tty; then
        return 1
    fi
    [[ -z $answer || $answer == [Yy]* ]]
}

pacman_flags=()
((YES)) && pacman_flags+=(--noconfirm)

cat <<EOF
${BOLD}Omarchy Guardian installer${RESET}
Reviews pacman packages, AUR builds, and Omarchy themes and plugins before
their code runs.
EOF

###############################################################################
step "Checking the system"
###############################################################################
((EUID != 0)) || fail "Run the installer as your user, not root; it asks for sudo when needed."
for tool in pacman makepkg sudo; do
    command -v "$tool" >/dev/null || fail "$tool is required (this installer is for Arch Linux / Omarchy)."
done
ok "Arch Linux with pacman and makepkg"

if command -v cargo >/dev/null; then
    ok "Rust toolchain: $(cargo --version)"
else
    note "No Rust toolchain found; it is needed to build Guardian."
    ask "Install it with: sudo pacman -S --needed rust?" || fail "Install Rust (pacman -S rust, or rustup), then run the installer again."
    sudo pacman -S --needed "${pacman_flags[@]}" rust
    ok "Rust toolchain: $(cargo --version)"
fi

version=$(sed -n 's/^pkgver=//p' "$PKG_DIR/PKGBUILD")-$(sed -n 's/^pkgrel=//p' "$PKG_DIR/PKGBUILD")
installed=$(pacman -Q omarchy-guardian 2>/dev/null | cut -d' ' -f2 || true)
if [[ -n $installed ]]; then
    ok "Installed: omarchy-guardian $installed; this checkout: $version"
else
    ok "Not installed yet; this checkout: $version"
fi

###############################################################################
step "Checking what this checkout is"
###############################################################################
# Guardian runs as root inside pacman, so what gets built matters. The keys
# releases are signed with come from the Guardian already installed, not
# from this checkout: a checkout that was tampered with could bring its own.
#
# What this check is worth: it is part of the checkout it checks. It catches
# honest mistakes (the wrong commit, a changed or added file, a tag that is
# not a signed release). Against a checkout someone tampered with it proves
# nothing, because this script would be theirs too. The check that does not
# depend on the checkout is the installed Guardian's own:
UPGRADE=/usr/lib/omarchy-guardian/upgrade
SIGNERS=/usr/share/omarchy-guardian/allowed_signers

# release_check <checkout> <keys file, or nothing>: says in one line what
# the checkout is.
#   signed <tag> <signer>  HEAD is the commit of the release tag <tag>,
#                          signed by one of the keys, and the working tree
#                          is that commit's tree: no file changed, none added
#   unchecked <tag>        the same, with no keys given to check the
#                          signature with
#   unsigned <why>         anything else
# The tag is looked up as refs/tags/<name> and verified by its object id,
# so another ref of the same name cannot stand in for it; it has to be a
# tag object (not a plain tag) that names HEAD's commit and carries the
# name it is stored under.
# The working tree is compared with the tagged tree file by file, hashing
# what is on disk. The index is not asked, so a file it was told to pass
# over (skip-worktree, assume-unchanged) is still compared, and git is told
# where the working tree is, whatever core.worktree says.
# Files that are not part of the tag count: cargo runs an added build.rs or
# .cargo/config.toml, and an added packaging/allowed_signers would be
# installed as the keys the next upgrade is checked against. Only what the
# tag's own top-level .gitignore names (the build's output) is passed over,
# whatever the checkout's index or .git/info/exclude say; the build below
# starts from an empty build directory, so what is passed over is not used.
# Git is asked with the settings given here and nobody's configuration
# file deciding: the checkout's own .git/config could name another program
# to "verify" with, or another keys file. It is still git running in this
# checkout, reading that file for everything not pinned here.
release_check() {
    local root=$1 signers=${2-} gitdir=$1/.git
    local head tag='' id name kind peeled line object='' type='' tagname=''
    local listing mode oid path file scratch others raw
    local -a files=() want=() got=()
    local -A in_tree=()
    if [[ -L $gitdir || (-e $gitdir && ! -d $gitdir) ]]; then
        printf 'unsigned %s\n' 'its .git is not a directory (a linked worktree or a submodule), so it cannot be checked'
        return
    fi
    if [[ ! -d $gitdir ]]; then
        printf 'unsigned %s\n' 'this is not a git checkout, so its origin cannot be checked'
        return
    fi
    local -a git=(
        /usr/bin/env GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1
        GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0
        /usr/bin/git --no-pager --git-dir="$gitdir" --work-tree="$root"
        -c core.bare=false -c "core.worktree=$root"
        -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.quotePath=false
        -c gpg.format=ssh -c gpg.ssh.program=/usr/bin/ssh-keygen
        -c "gpg.ssh.allowedSignersFile=$signers" -c gpg.ssh.revocationFile=/dev/null
        -c gpg.program=/usr/bin/false -c gpg.openpgp.program=/usr/bin/false
        -c gpg.x509.program=/usr/bin/false
    )
    if ! head=$("${git[@]}" rev-parse --verify -q 'HEAD^{commit}'); then
        printf 'unsigned %s\n' 'this is not a git checkout with a commit, so its origin cannot be checked'
        return
    fi

    # The release tag at HEAD: a tag object under refs/tags/ that names
    # HEAD's commit, the highest version first.
    while read -r name kind peeled; do
        name=${name#refs/tags/}
        if [[ $kind == tag && $peeled == "$head" && $name =~ ^v[0-9]+(\.[0-9]+)*(-[0-9]+)?$ ]]; then
            tag=$name
            break
        fi
    done < <("${git[@]}" for-each-ref --sort=-version:refname \
        --format='%(refname) %(objecttype) %(*objectname)' refs/tags/)
    if [[ -z $tag ]] || ! id=$("${git[@]}" rev-parse --verify -q "refs/tags/$tag"); then
        printf 'unsigned commit %s is not a release tag\n' "${head:0:12}"
        return
    fi
    while IFS= read -r line; do
        [[ -n $line ]] || break
        case $line in
            'object '*) [[ -n $object ]] || object=${line#object } ;;
            'type '*) [[ -n $type ]] || type=${line#type } ;;
            'tag '*) [[ -n $tagname ]] || tagname=${line#tag } ;;
        esac
    done < <("${git[@]}" cat-file tag "$id")
    if [[ $object != "$head" || $type != commit || $tagname != "$tag" ]]; then
        printf 'unsigned the tag stored as %s is not the signed tag of this commit under that name\n' "$tag"
        return
    fi

    # Every file of the tagged tree against what is on disk.
    if ! listing=$("${git[@]}" ls-tree -r "$head"); then
        printf 'unsigned the files of %s cannot be listed\n' "$tag"
        return
    fi
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        read -r mode kind oid <<<"${line%%$'\t'*}"
        path=${line#*$'\t'}
        file=$root/$path
        in_tree[$path]=1
        case $mode in
            100644 | 100755)
                # A name git had to quote is not hashed: it counts as changed.
                if [[ $path == \"* || ! -f $file || -L $file ]] ||
                    { [[ $mode == 100755 ]] && [[ ! -x $file ]]; } ||
                    { [[ $mode == 100644 ]] && [[ -x $file ]]; }; then
                    printf 'unsigned this checkout has local changes on top of %s: %s\n' "$tag" "$path"
                    return
                fi
                files+=("$file")
                want+=("$oid")
                ;;
            120000)
                if [[ ! -L $file ]] ||
                    [[ $(printf '%s' "$(readlink -- "$file")" | "${git[@]}" hash-object --stdin) != "$oid" ]]; then
                    printf 'unsigned this checkout has local changes on top of %s: %s\n' "$tag" "$path"
                    return
                fi
                ;;
            *)
                printf 'unsigned %s has an entry that cannot be compared: %s\n' "$tag" "$path"
                return
                ;;
        esac
    done <<<"$listing"
    if ((${#files[@]})); then
        # --no-filters: the bytes on disk, with no conversion and no filter
        # program the checkout's configuration could name.
        mapfile -t got < <(printf '%s\n' "${files[@]}" | "${git[@]}" hash-object --no-filters --stdin-paths)
        for line in "${!want[@]}"; do
            if [[ ${got[line]-} != "${want[line]}" ]]; then
                printf 'unsigned this checkout has local changes on top of %s: %s\n' "$tag" "${files[line]#"$root"/}"
                return
            fi
        done
    fi

    # Every file on disk that is not in the tagged tree. An index that does
    # not exist makes every file one git has never heard of, so the
    # checkout's index cannot vouch for an added file.
    scratch=$(/usr/bin/mktemp -d) || {
        printf 'unsigned %s\n' 'no temporary directory to compare the files in'
        return
    }
    "${git[@]}" cat-file blob "$head:.gitignore" >"$scratch/exclude" 2>/dev/null || : >"$scratch/exclude"
    if ! others=$(GIT_INDEX_FILE="$scratch/no-index" "${git[@]}" ls-files --others \
        --exclude-from="$scratch/exclude"); then
        /usr/bin/rm -rf -- "$scratch"
        printf 'unsigned the files of this checkout cannot be listed\n'
        return
    fi
    /usr/bin/rm -rf -- "$scratch"
    while IFS= read -r path; do
        if [[ -n $path && -z ${in_tree[$path]-} ]]; then
            printf 'unsigned this checkout has files that are not part of %s: %s\n' "$tag" "$path"
            return
        fi
    done <<<"$others"

    if [[ -z $signers ]]; then
        printf 'unchecked %s\n' "$tag"
        return
    fi
    if [[ ! -x /usr/bin/ssh-keygen ]]; then
        printf 'unsigned the signature of %s cannot be checked without ssh-keygen (pacman -S openssh)\n' "$tag"
        return
    fi
    # A signature of another kind would be checked by another program. Git's
    # exit status and ssh-keygen's own words are both required; what they
    # said is shown when the check fails.
    if ! "${git[@]}" cat-file tag "$id" | grep -q -- '-----BEGIN SSH SIGNATURE-----'; then
        printf 'unsigned %s is not signed by a release key your installed Guardian knows (it carries no SSH signature)\n' "$tag"
        return
    fi
    if ! raw=$("${git[@]}" verify-tag --raw "$id" 2>&1) ||
        [[ ! $raw =~ (^|$'\n')Good\ \"git\"\ signature\ for\ ([^[:space:]]+)\ with\ [^[:space:]]+\ key\ SHA256: ]]; then
        printf '%s\n' "$raw" >&2
        printf 'unsigned %s is not signed by a release key your installed Guardian knows\n' "$tag"
        return
    fi
    printf 'signed %s %s\n' "$tag" "${BASH_REMATCH[2]}"
}

keys=''
[[ -f $SIGNERS && ! -L $SIGNERS && $(stat -c %u -- "$SIGNERS") == 0 ]] && keys=$SIGNERS
# With installed keys there is a check that does not depend on this checkout.
stronger_check() {
    [[ -n $keys ]] || return 0
    note "This check is part of the checkout it checks, so it only guards against mistakes."
    if [[ -x $UPGRADE ]]; then
        note "The check that is not: run $UPGRADE in this checkout. The installed"
        note "Guardian then verifies the release itself and builds a clean export of it."
    fi
}

if [[ -n $VERIFIED ]]; then
    # Started by the installed Guardian's upgrade check, in the export it
    # made of the release it verified. This is taken at its word only in a
    # directory without .git, where the check below could say nothing but
    # "not a git checkout"; typed by hand it answers that question, no more.
    if [[ -e $ROOT/.git || -L $ROOT/.git ]]; then
        fail "--verified-by-installed is for the export $UPGRADE makes, not for a git checkout. Run ./install.sh without it."
    fi
    ok "Release ${VERIFIED%%:*} (commit ${VERIFIED#*:}), verified and exported by $UPGRADE before this installer was started"
else
    state=$(release_check "$ROOT" "$keys")
    case $state in
        signed\ *)
            read -r _ tag signer <<<"$state"
            ok "This checkout matches release $tag, signed by $signer: no file changed, none added"
            stronger_check
            ;;
        unchecked\ *)
            ok "This checkout matches release tag ${state#unchecked }: no file changed, none added"
            note "The installed Guardian carries no release keys, so the signature is not checked."
            note "To check it yourself, see 'Verifying a release' in docs/install.md."
            ;;
        *)
            why=${state#unsigned }
            note "${why^}."
            if [[ -n $keys ]]; then
                note "This is not a release signed by a key your installed Guardian knows."
                stronger_check
                # Never answered by --yes: an unattended run must not wave an
                # unsigned build through.
                answer=''
                read -r -p "  Build and install it anyway? [y/N] " answer </dev/tty || true
                [[ $answer == [Yy]* ]] || fail "Not installed. Check out a signed release tag (git tag -l 'v*')."
            else
                note "The installed Guardian carries no release keys, so the signature is not checked."
            fi
            ;;
    esac
fi

###############################################################################
if [[ $installed == "$version" ]] && ((!REINSTALL)); then
    step "Skipping the build: omarchy-guardian $version is already installed (--reinstall to redo it)"
else
    step "Building omarchy-guardian $version"
    ###########################################################################
    log=${XDG_CACHE_HOME:-$HOME/.cache}/omarchy-guardian/install-build.log
    mkdir -p "${log%/*}"
    # -d: the build needs only cargo, which was checked above (rustup's cargo
    # is not a pacman package); pacman installs the runtime dependencies.
    # --cleanbuild: makepkg empties its build directory first, cargo's
    # target directory in it included. That directory is one the check above
    # passes over, and cargo would link what it found there with a fresh
    # enough date instead of building it.
    if ! (cd "$PKG_DIR" && makepkg --cleanbuild --force --nodeps --noconfirm) >"$log" 2>&1; then
        tail -n 20 "$log" >&2
        fail "The build failed; the full log is in $log"
    fi
    archive=$(cd "$PKG_DIR" && makepkg --packagelist | grep -v -- '-debug-' | head -n 1)
    [[ -f $archive ]] || fail "The build did not produce $archive"
    ok "Built ${archive##*/} (tests passed)"

    ###########################################################################
    step "Installing with pacman"
    ###########################################################################
    if [[ -n $installed && -e /etc/pacman.d/hooks/omarchy-guardian.hook ]]; then
        note "Your installed Guardian ($installed) reviews this package first."
    fi
    until sudo pacman -U "${pacman_flags[@]}" "$archive"; do
        note "pacman did not install the package."
        note "If Guardian's own review reported INCOMPLETE or AI REVIEW UNAVAILABLE, a retry usually passes."
        ask "Try again?" || fail "Not installed. Run the installer again when ready."
    done
    ok "Installed omarchy-guardian $(pacman -Q omarchy-guardian | cut -d' ' -f2)"
fi

###############################################################################
step "Checking the AI reviewer"
###############################################################################
# How to start this installer again. The export it runs from after the
# installed Guardian's upgrade check is gone by then.
again=$ROOT/install.sh
[[ -n $VERIFIED ]] && again="$UPGRADE (in your checkout)"
root_owned() { [[ -x $1 && $(stat -c %u -- "$1") == 0 ]]; }
# claude-code is in Omarchy's repository, not in Arch's own: it is offered
# only where a configured repository has it.
in_a_repository() { pacman -Si "$1" >/dev/null 2>&1; }
has_claude=0 has_opencode=0
command -v claude >/dev/null && has_claude=1
command -v opencode >/dev/null && has_opencode=1

if ((has_claude)); then
    ok "Claude Code: $(command -v claude)"
    if root_owned /usr/bin/claude; then
        ok "The pacman gate can use the root-owned /usr/bin/claude"
    else
        note "The pacman gate only runs a root-owned reviewer, and /usr/bin/claude is missing."
        if ! in_a_repository claude-code; then
            note "None of your repositories has claude-code. For the pacman gate, install a"
            note "root-owned OpenCode (sudo pacman -S --needed extra/opencode) and choose an"
            note "OpenCode model for pacman in: omarchy-guardian tui"
        elif ask "Install it with: sudo pacman -S --needed claude-code?"; then
            sudo pacman -S --needed "${pacman_flags[@]}" claude-code
            ok "Installed claude-code"
        fi
    fi
elif ((has_opencode)); then
    ok "OpenCode: $(command -v opencode)"
    root_owned /usr/bin/opencode ||
        note "The pacman gate needs a root-owned OpenCode: sudo pacman -S --needed extra/opencode"
else
    note "No AI reviewer found. Guardian works best with Claude Code (your Claude login)."
    if in_a_repository claude-code; then
        reviewer=claude-code reviewer_name='Claude Code'
        reviewer_login="Log in once by running ${BOLD}claude${RESET}"
    else
        note "None of your repositories has claude-code (it is in Omarchy's, not in Arch's)."
        reviewer=extra/opencode reviewer_name=OpenCode
        reviewer_login="Set up a provider once by running ${BOLD}opencode${RESET}"
    fi
    if ask "Install $reviewer_name with: sudo pacman -S --needed $reviewer?"; then
        sudo pacman -S --needed "${pacman_flags[@]}" "$reviewer"
        cat <<EOF

  $reviewer_name is installed. $reviewer_login, then run
  ${BOLD}$again${RESET} again to finish.
EOF
        exit 0
    fi
    note "Continuing without AI: choose the 'local-only' profile in the setup below."
fi

###############################################################################
step "Settings"
###############################################################################
user_config=${XDG_CONFIG_HOME:-$HOME/.config}/omarchy-guardian/config.toml
if [[ -f $user_config ]]; then
    ok "Keeping your settings in $user_config (change them with: omarchy-guardian tui)"
else
    omarchy-guardian setup || fail "Setup did not finish; run the installer again, or: omarchy-guardian setup"
fi

# `protect` and `test` arrived in 0.4.2; an older installed Guardian (the
# build was skipped) has neither.
has_command() {
    local usage
    usage=$(omarchy-guardian 2>&1 || true)
    [[ $usage == *"omarchy-guardian $1 "* ]]
}

###############################################################################
step "Turning protection on"
###############################################################################
if has_command protect; then
    protect=(omarchy-guardian protect)
    ((YES)) && protect+=(--yes)
    "${protect[@]}" || note "Some protection is still off; turn it on later with: omarchy-guardian protect"
else
    note "This Guardian version cannot do it from here; open omarchy-guardian tui and choose Protect everything."
fi

###############################################################################
if grep -qs '^profile = "local-only"' "$user_config"; then
    step "Skipping the reviewer test (local-only: no AI)"
elif ! has_command test; then
    step "Skipping the reviewer test (test it in omarchy-guardian tui: press t)"
else
    step "Testing the reviewer"
    ###########################################################################
    omarchy-guardian test ||
        note "The reviewer test failed; check the model with: omarchy-guardian tui (press t to test again)"
fi

# The installed Guardian's own check, once it is there with its keys.
upgrade_with='git pull && ./install.sh'
if [[ -x $UPGRADE && -f $SIGNERS ]]; then
    upgrade_with="git pull && $UPGRADE   (in your checkout)"
fi
cat <<EOF

${GREEN}${BOLD}Omarchy Guardian is installed.${RESET}
  Settings:  omarchy-guardian tui   (or Omarchy menu › Setup › Guardian)
  Upgrade:   $upgrade_with
EOF
