#!/bin/bash
# Measures the AI review against known cases, so a prompt, scope or model
# change can be checked for false denies and missed attacks before release.
#
# Each case under cases/ is reviewed through the gate that meets it in real
# use, and its directory says what the review must decide:
#   cases/scriptlet/{clear,block}/NAME.install  an install script, packaged and
#                                               reviewed by the pacman gate
#   cases/payload/{clear,block}/NAME/           package files that run on their
#                                               own (hooks, units, sudoers,
#                                               polkit, ...), by the pacman gate
#   cases/aur/{clear,block}/NAME/               a PKGBUILD and its local
#                                               sources, by the yay makepkg gate
#   cases/system/{clear,block}/NAME/{etc,usr,home}/  files already on a system,
#                                               found by `sweep`: etc and usr
#                                               overlay the real ones in a
#                                               bwrap sandbox, home is the home
#                                               directory
# clear passes only on a clear or warned review that ran (exit 0), block only on
# findings (exit 1). An incomplete or unavailable review fails either way.
# A system case is judged by the AI's own medium or high findings on the
# planted files only: the rest of the real system (and its root-only files)
# would otherwise decide the sweep's exit code, and local rules would hide
# whether the AI saw it.
# Cases measure the AI review, so a clear case should not match a local rule:
# the packages here are local (pacman -U), where a local finding blocks even
# after a clear AI review.
#
# Nothing is installed or built: the pacman gate is run by a stand-in parent
# named pacman, and the makepkg gate by a makepkg that runs only the
# --printsrcinfo and source extraction steps for real. Every run starts with an
# empty review memory, so no verdict comes from the cache.
#
# The pacman gate reviews with the system config and a root-owned reviewer
# (/usr/bin/opencode or /usr/bin/claude), as it does for real; the makepkg gate
# with the user config.
#
# Usage:
#   cargo build --release
#   bash tests/ai-eval/run.sh [FILTER...]
#
# FILTER selects the cases whose path (e.g. aur/block/base64-prepare)
# contains it. RUNS=N repeats each case (default 1), JOBS=N sets how many
# reviews run at once (default 3), GUARDIAN picks the binary and
# GUARDIAN_EVAL_KEEP=1 keeps the logs.
set -uo pipefail

EVAL=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PROJECT=$(cd -- "$EVAL/../.." && pwd -P)
GUARDIAN=${GUARDIAN:-$PROJECT/target/release/omarchy-guardian}
RUNS=${RUNS:-1}
JOBS=${JOBS:-3}
WORK=$(mktemp -d -t guardian-eval-XXXXXX)

if [[ ! -x $GUARDIAN ]]; then
    printf 'Build Guardian first: cargo build --release\n' >&2
    exit 2
fi
for tool in bsdtar makepkg bwrap jq; do
    command -v "$tool" >/dev/null || {
        printf 'missing required tool: %s\n' "$tool" >&2
        exit 77
    }
done

cleanup() {
    [[ -n ${GUARDIAN_EVAL_KEEP:-} ]] || rm -rf -- "$WORK"
}
trap cleanup EXIT

# The stand-in pacman stays the gate's parent, because the gate reads the
# transaction from its parent's argv and working directory.
cat >"$WORK/pacman" <<'EOF'
#!/bin/sh
printf '%s\n' "$TARGET" | "$GUARDIAN" pacman-hook --pacman-pid $$ --cwd "$PWD"
EOF
cat >"$WORK/makepkg" <<'EOF'
#!/bin/sh
case " $* " in
*" --printsrcinfo "* | *" --nobuild "*) exec /usr/bin/makepkg "$@" ;;
esac
printf 'built\n' >"$BUILT"
EOF
chmod 755 "$WORK/pacman" "$WORK/makepkg"

# package <name> <install-script-or-empty> <tree-or-empty> <archive>
package() {
    local name=$1 install=$2 tree=$3 archive=$4
    local root=${archive%.pkg.tar.zst}.root
    mkdir -p "$root/usr/bin"
    [[ -z $tree ]] || cp -a -- "$tree/." "$root/"
    {
        printf 'pkgname = %s\npkgbase = %s\npkgver = 1-1\n' "$name" "$name"
        printf 'pkgdesc = guardian eval case\nurl = https://example.test\n'
        printf 'builddate = 0\npackager = Tester\nsize = 0\narch = x86_64\nlicense = MIT\n'
    } >"$root/.PKGINFO"
    printf '#!/bin/sh\necho %s\n' "$name" >"$root/usr/bin/$name"
    chmod 755 "$root/usr/bin/$name"
    local -a members=(.PKGINFO)
    if [[ -n $install ]]; then
        cp -- "$install" "$root/.INSTALL"
        members+=(.INSTALL)
    fi
    (cd "$root" && bsdtar --zstd --format pax --uid 0 --gid 0 -cf "$archive" "${members[@]}" *) ||
        return 2
    rm -rf -- "$root"
}

# sweep_case <case-dir> <work-dir> <log>: sweeps a sandbox with the case's
# files in place and returns 1 when the AI flagged a planted file, 0 when
# the AI reviewed and flagged none, 2 when there was no AI review.
sweep_case() {
    local case=$1 dir=$2 log=$3
    local home=$dir/home
    mkdir -p "$home/.cache" "$dir/empty"
    [[ -d $case/home ]] && cp -a -- "$case/home/." "$home/"
    local -a overlays=()
    local top file
    # /etc always gets an overlay, so the tmpfs over /etc/omarchy-guardian
    # below can be made even where that directory does not exist.
    for top in etc usr; do
        if [[ -d $case/$top ]]; then
            overlays+=(--overlay-src "/$top" --overlay-src "$case/$top" --tmp-overlay "/$top")
        elif [[ $top == etc ]]; then
            overlays+=(--overlay-src /etc --tmp-overlay /etc)
        fi
    done
    # The reviewer's login and configuration, in the throwaway home.
    local -a binds=()
    [[ -d $HOME/.claude ]] && binds+=(--bind "$HOME/.claude" "$home/.claude")
    [[ -f $HOME/.claude.json ]] && binds+=(--bind "$HOME/.claude.json" "$home/.claude.json")
    [[ -d $HOME/.local/share/opencode ]] && binds+=(--bind "$HOME/.local/share/opencode" "$home/.local/share/opencode")
    # Guardian's own settings (the model); XDG_CONFIG_HOME stays unset, since
    # the Claude CLI then looks for its login under it.
    local config=${XDG_CONFIG_HOME:-$HOME/.config}
    for name in omarchy-guardian opencode; do
        [[ -d $config/$name ]] && binds+=(--ro-bind "$config/$name" "$home/.config/$name")
        mkdir -p "$home/.config/$name"
    done
    mkdir -p "$home/.local/share/opencode"
    touch "$home/.claude.json"
    mkdir -p "$home/.claude"
    # The overlay makes the system file look owned by someone else, which
    # Guardian rightly refuses; without one, the user file decides.
    # /tmp first: the run directory lives under it.
    # Its own process namespace: the host's processes are not reviewed.
    bwrap --ro-bind / / "${overlays[@]}" --tmpfs /etc/omarchy-guardian --tmpfs /tmp \
        --bind "$dir" "$dir" "${binds[@]}" \
        --unshare-pid --proc /proc --dev /dev \
        --setenv HOME "$home" --setenv PATH /usr/bin:/bin \
        --unsetenv XDG_CONFIG_HOME \
        --setenv XDG_STATE_HOME "$dir/state" --setenv XDG_CACHE_HOME "$home/.cache" \
        --new-session -- "$GUARDIAN" sweep --json </dev/null >"$dir/sweep.json" 2>"$log"
    local -a planted=()
    while IFS= read -r file; do
        file=${file#"$case/"}
        case $file in
        home/*) planted+=("~/${file#home/}") ;;
        *) planted+=("/$file") ;;
        esac
    done < <(find "$case" -type f)
    printf 'planted: %s\n' "${planted[*]}" >>"$log"
    jq '.ai' "$dir/sweep.json" >>"$log" 2>/dev/null
    # An inconclusive review is no verdict either way.
    jq -e '.ai | length > 0 and all(.[]; .status != "inconclusive")' "$dir/sweep.json" >/dev/null 2>&1 ||
        return 2
    # Low-severity notes are remarks, not a judgement of danger. The model
    # may add `:line` or spell out the home directory.
    jq -e --arg home "$home" --args '
        [.ai[].findings[] | select(.severity != "low" and .path != null) | .path | sub(":[0-9]+$"; "")] as $flagged
        | any($ARGS.positional[]; . as $p
            | any($flagged[]; . == $p or (($p | startswith("~/")) and . == $home + $p[1:])))' \
        "${planted[@]}" <"$dir/sweep.json" >/dev/null && return 1
    return 0
}

# review <case-path> <run> <log>: prints the exit code of the gate
review() {
    local case=$1 run=$2 log=$3
    local kind=${case%%/*} name=${case##*/}
    name=eval-${name%.install}
    local dir=$WORK/runs/$run-${case//\//-}
    mkdir -p "$dir/state"
    # Blocks are expected here; GUARDIAN_EVAL_NOTIFY=1 shows them anyway.
    [[ -n ${GUARDIAN_EVAL_NOTIFY:-} ]] || export OMARCHY_GUARDIAN_NO_NOTIFY=1
    export XDG_STATE_HOME=$dir/state GUARDIAN
    case $kind in
    scriptlet | payload)
        local archive=$dir/$name-1-1-x86_64.pkg.tar.zst
        if [[ $kind == scriptlet ]]; then
            package "$name" "$EVAL/cases/$case" "" "$archive"
        else
            package "$name" "" "$EVAL/cases/$case" "$archive"
        fi || return 2
        (cd "$dir" && TARGET=$name "$WORK/pacman" -U "$archive") </dev/null >"$log" 2>&1
        ;;
    system)
        sweep_case "$EVAL/cases/$case" "$dir" "$log"
        return
        ;;
    aur)
        cp -a -- "$EVAL/cases/$case" "$dir/$name"
        (cd "$dir/$name" && BUILT=$dir/built "$GUARDIAN" makepkg-gate -- "$WORK/makepkg" -s --noconfirm) \
            </dev/null >"$log" 2>&1
        local status=$?
        # A gate that exits 0 without starting the build did not allow it.
        ((status != 0)) || [[ -e $dir/built ]] || status=2
        return "$status"
        ;;
    esac
}

cases=()
while IFS= read -r path; do
    path=${path#"$EVAL/cases/"}
    if (($# == 0)); then
        cases+=("$path")
    else
        for filter; do
            [[ $path == *"$filter"* ]] && { cases+=("$path"); break; }
        done
    fi
done < <(find "$EVAL/cases" -mindepth 3 -maxdepth 3 | sort)
((${#cases[@]} > 0)) || { printf 'no cases match\n' >&2; exit 2; }

mkdir -p "$WORK/logs" "$WORK/results"
printf 'Reviewing %d case(s) x %d run(s) with %s\n\n' "${#cases[@]}" "$RUNS" "$GUARDIAN"
running=0
for case in "${cases[@]}"; do
    for ((run = 1; run <= RUNS; run++)); do
        (
            log=$WORK/logs/${case//\//-}.$run.log
            review "$case" "$run" "$log"
            status=$?
            grep -q 'UNAVAILABLE' "$log" && status=2
            printf '%s\n' "$status" >"$WORK/results/${case//\//-}.$run"
        ) &
        if ((++running >= JOBS)); then
            wait -n
            running=$((running - 1))
        fi
    done
done
wait

failed=0
for case in "${cases[@]}"; do
    want=0
    [[ $case == */block/* ]] && want=1
    passes=0 verdicts=""
    for ((run = 1; run <= RUNS; run++)); do
        status=$(cat "$WORK/results/${case//\//-}.$run" 2>/dev/null || echo 2)
        case $status in
        0) verdicts+=C ;;
        1) verdicts+=F ;;
        *) verdicts+=I ;;
        esac
        [[ $status == "$want" ]] && passes=$((passes + 1))
    done
    if ((passes == RUNS)); then
        printf 'ok   %-45s %s\n' "$case" "$verdicts"
    else
        printf 'FAIL %-45s %s  (%d/%d)\n' "$case" "$verdicts" "$passes" "$RUNS"
        failed=$((failed + 1))
    fi
done

printf '\nC clear  F findings  I incomplete or unavailable\n'
if ((failed > 0)); then
    GUARDIAN_EVAL_KEEP=1
    printf '%d case(s) failed; logs in %s/logs\n' "$failed" "$WORK"
    exit 1
fi
printf 'ALL %d CASE(S) PASSED\n' "${#cases[@]}"
