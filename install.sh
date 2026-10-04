#!/bin/bash
# Installs or upgrades Omarchy Guardian from this checkout and turns its
# protection on:
#   1. checks for a Rust toolchain (rustup's or Arch's)
#   2. builds the Arch package from this checkout
#   3. installs it with pacman, by absolute path so any installed Guardian
#      pacman hook can find the archive
#   4. makes sure there is an AI reviewer (Claude Code or OpenCode)
#   5. runs the guided setup on a first install
#   6. turns every gate on (`omarchy-guardian protect`), showing each step
#   7. tests the reviewer with a malicious and a harmless sample
#
# Run it as your user from anywhere; sudo is asked for when a step needs it.
# Safe to run again: steps that are already done are skipped.
#
# Usage: ./install.sh [--yes] [--reinstall]
#   --yes        answer yes to the installer's own questions and to pacman
#                (the guided setup still asks its questions)
#   --reinstall  rebuild and reinstall even when this version is installed
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd -P)
PKG_DIR=$ROOT/packaging/arch
YES=0
REINSTALL=0

for arg; do
    case $arg in
        -y | --yes) YES=1 ;;
        --reinstall) REINSTALL=1 ;;
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
SIGNERS=/usr/share/omarchy-guardian/allowed_signers

# release_check <checkout> <keys file, or nothing>: says in one line what
# the checkout is.
#   signed <tag>       exactly a release tag signed by one of the keys, with
#                      no file changed and none added
#   unchecked <tag>    exactly a tag with nothing changed or added; no keys
#                      were given to check its signature with
#   unsigned <why>     anything else
# Files that are not part of the tag count: cargo runs an added build.rs or
# .cargo/config.toml, and an added packaging/allowed_signers would be
# installed as the keys the next upgrade is checked against. Only what the
# tag's own top-level .gitignore names (the build's output) is passed over,
# whatever the checkout's .git/info/exclude says.
# Git is asked with the settings given here and nobody's configuration
# file deciding: the checkout's own .git/config could name another program
# to "verify" with, or another keys file.
release_check() {
    local root=$1 signers=${2-} tag commit added
    local -a git=(
        /usr/bin/env GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1
        git -C "$root"
        -c core.fsmonitor=false -c core.hooksPath=/dev/null
        -c gpg.format=ssh -c gpg.ssh.program=/usr/bin/ssh-keygen
        -c "gpg.ssh.allowedSignersFile=$signers" -c gpg.ssh.revocationFile=/dev/null
        -c gpg.program=/usr/bin/false -c gpg.openpgp.program=/usr/bin/false
        -c gpg.x509.program=/usr/bin/false
    )
    if ! "${git[@]}" rev-parse --git-dir >/dev/null 2>&1; then
        printf 'unsigned %s\n' 'this is not a git checkout, so its origin cannot be checked'
        return
    fi
    commit=$("${git[@]}" rev-parse --short=12 HEAD 2>/dev/null)
    if ! tag=$("${git[@]}" describe --exact-match --tags HEAD 2>/dev/null) || [[ -z $tag ]]; then
        printf 'unsigned commit %s is not a release tag\n' "$commit"
        return
    fi
    if [[ -n $("${git[@]}" status --porcelain --untracked-files=no 2>&1) ]]; then
        printf 'unsigned this checkout has local changes on top of %s\n' "$tag"
        return
    fi
    if ! added=$("${git[@]}" ls-files --others --directory --no-empty-directory --exclude-from="$root/.gitignore" 2>&1) ||
        [[ -n $added ]]; then
        printf 'unsigned this checkout has files that are not part of %s: %s\n' "$tag" \
            "$(printf '%s' "$added" | head -n 3 | tr '\n' ' ')"
        return
    fi
    if [[ -z $signers ]]; then
        printf 'unchecked %s\n' "$tag"
        return
    fi
    if [[ ! -x /usr/bin/ssh-keygen ]]; then
        printf 'unsigned the signature of %s cannot be checked without ssh-keygen (pacman -S openssh)\n' "$tag"
        return
    fi
    # A signature of another kind would be checked by another program.
    if ! "${git[@]}" cat-file tag "$tag" 2>/dev/null | grep -q -- '-----BEGIN SSH SIGNATURE-----' ||
        ! "${git[@]}" verify-tag "$tag" >/dev/null 2>&1; then
        printf 'unsigned %s is not signed by a release key your installed Guardian knows\n' "$tag"
        return
    fi
    printf 'signed %s\n' "$tag"
}

keys=''
[[ -f $SIGNERS && $(stat -c %u -- "$SIGNERS") == 0 ]] && keys=$SIGNERS
state=$(release_check "$ROOT" "$keys")
case $state in
    signed\ *) ok "${state#signed } is signed by a release key your installed Guardian knows, with nothing changed or added" ;;
    unchecked\ *)
        ok "Release tag ${state#unchecked }, with nothing changed or added"
        note "The installed Guardian carries no release keys, so the signature is not checked."
        ;;
    *)
        why=${state#unsigned }
        note "${why^}."
        if [[ -n $keys ]]; then
            note "This is not a release signed by a key your installed Guardian knows."
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
    if ! (cd "$PKG_DIR" && makepkg --force --nodeps --noconfirm) >"$log" 2>&1; then
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
root_owned() { [[ -x $1 && $(stat -c %u -- "$1") == 0 ]]; }
has_claude=0 has_opencode=0
command -v claude >/dev/null && has_claude=1
command -v opencode >/dev/null && has_opencode=1

if ((has_claude)); then
    ok "Claude Code: $(command -v claude)"
    if root_owned /usr/bin/claude; then
        ok "The pacman gate can use the root-owned /usr/bin/claude"
    else
        note "The pacman gate only runs a root-owned reviewer, and /usr/bin/claude is missing."
        if ask "Install it with: sudo pacman -S --needed claude-code?"; then
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
    if ask "Install Claude Code with: sudo pacman -S --needed claude-code?"; then
        sudo pacman -S --needed "${pacman_flags[@]}" claude-code
        cat <<EOF

  Claude Code is installed. Log in once by running ${BOLD}claude${RESET}, then run
  ${BOLD}$ROOT/install.sh${RESET} again to finish.
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

cat <<EOF

${GREEN}${BOLD}Omarchy Guardian is installed.${RESET}
  Settings:  omarchy-guardian tui   (or Omarchy menu › Setup › Guardian)
  Upgrade:   git pull && ./install.sh
EOF
