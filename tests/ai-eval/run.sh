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
#   cases/theme/{clear,block}/NAME/             an Omarchy theme, and
#   cases/plugin/{clear,block}/NAME/            an Omarchy shell plugin, each
#                                               by `guard --class`, as the
#                                               theme and plugin handlers do
#   cases/upgrade/{clear,block}/NAME/{class,v1/,v2/}  two versions of one
#                                               source of the class named in
#                                               the file `class`: v1 is
#                                               reviewed and must be approved,
#                                               then v2 is reviewed against it
#                                               with the same review memory;
#                                               v2's review is the verdict
# clear passes only on a clear or warned review that ran (exit 0), block only on
# findings (exit 1). An incomplete or unavailable review fails either way.
# Under the default profile the low remarks of a clear AI verdict do not block
# (docs/review.md), so a block case the AI answers that way counts as missed,
# and a clear case with such remarks passes. A block case passes on exit 1
# whatever blocked it, a local rule included, so the exit code alone does not
# show a reviewer that answered a block case with clear and low findings.
# Each gate run therefore also records whether a report of it had that answer
# (see `clear_with_low`): AI remarks, or low AI findings alone beside a clear
# verdict, which count as findings where a local rule matched in the same
# files. The count is printed beside each case's pass rate as `clear+low`,
# and the run ends with the block cases that had it in any run, and the clear
# cases that passed only because remarks do not block. This changes no pass
# or fail. A system case shows "-": the sweep counts every AI finding, and
# its cases are judged by severity already.
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
# --printsrcinfo and source extraction steps for real (in a bwrap sandbox
# where it is /usr/bin/makepkg, since the gate's own jail shows nothing of
# this run's directory); the command `guard` would start only leaves a
# marker. Every run starts with an empty review memory, so no verdict comes
# from the cache (an upgrade case keeps its own between its two versions).
# Reports of the blocks are saved in the run's own directory, not in the
# real reports directory, and no pop-up is shown.
#
# No case here may need an answer on the terminal: a build of prebuilt
# programs, or a recipe whose sources the gate cannot follow, ends as
# NOT CONFIRMED (exit 2) and is counted incomplete.
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
# contains it. RUNS=N repeats each case (default 3: one run says little about
# a model that answers differently now and then), JOBS=N sets how many
# reviews run at once (default 3), GUARDIAN picks the binary and
# GUARDIAN_EVAL_KEEP=1 keeps the logs. Each case gets a line with its pass
# rate, and the run ends with the rates of the block and the clear cases.
# The exit status is 1 when any case passed less than every run.
set -uo pipefail

EVAL=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PROJECT=$(cd -- "$EVAL/../.." && pwd -P)
GUARDIAN=${GUARDIAN:-$PROJECT/target/release/omarchy-guardian}
RUNS=${RUNS:-3}
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
*" --printsrcinfo "* | *" --nobuild "*) exec /usr/bin/makepkg.real "$@" ;;
esac
printf 'built\n' >"$BUILT"
EOF
chmod 755 "$WORK/pacman" "$WORK/makepkg"
mkdir -p "$WORK/usr-layer/bin"
cp -- /usr/bin/makepkg "$WORK/usr-layer/bin/makepkg.real"

# makepkg_sandbox <command...>: runs the makepkg gate where /usr/bin/makepkg
# is the stand-in and the real one is beside it as makepkg.real.
#
# The gate lists and fetches the sources by running the makepkg it is given
# inside its own jail, which shows /usr and the build directory and nothing
# else of this run's directory: a stand-in kept there would not be found,
# and every aur case would end incomplete. Everything else is the host's,
# writable as it is (the reviewer keeps its login and session state in the
# home), but for the system settings file: in this sandbox's user namespace
# it does not look root-owned, and the gate would refuse every case for it.
# It is hidden where there is one, so the user file decides; a mount point
# cannot be made in /etc where there is none, and then nothing is to hide.
makepkg_sandbox() {
    local -a hidden=()
    [[ -d /etc/omarchy-guardian ]] && hidden=(--tmpfs /etc/omarchy-guardian)
    bwrap --dev-bind / / "${hidden[@]}" \
        --overlay-src /usr --overlay-src "$WORK/usr-layer" --tmp-overlay /usr \
        --ro-bind "$WORK/makepkg" /usr/bin/makepkg -- "$@"
}

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

# clear_with_low <log>: whether the reviewer answered some part of the case
# with a clear verdict and low findings only. Read from the printed report:
# the verdict box's "Remarks: 2 low · ..." line (those chunks were clear and
# their findings did not count), or a report whose "AI findings" table holds
# LOW rows alone while no chunk of it was SUSPICIOUS (clear, and the low
# findings counted: a local rule matched beside them, or the profile is
# strict). An AUR case's log holds two reports, the recipe's and the upstream
# sources'; either counts.
clear_with_low() {
    [[ -r $1 ]] || return 1
    grep -Eq 'Remarks: [0-9]+ low' "$1" && return 0
    awk '
        function ended() { if (low && !higher && !suspicious) found = 1 }
        /^╭─ Omarchy Guardian/ { ended(); low = higher = suspicious = table = 0 }
        /^  AI review .*SUSPICIOUS/ { suspicious = 1 }
        /^  AI findings$/ { table = 1; next }
        table && /^$/ { table = 0 }
        table && /^  │ LOW / { low = 1 }
        table && /^  │ (MEDIUM|HIGH) / { higher = 1 }
        END { ended(); exit !found }
    ' "$1"
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
    # Reports of the expected blocks stay with the run, out of the real
    # reports directory and the bar.
    export XDG_STATE_HOME=$dir/state XDG_CACHE_HOME=$dir/cache GUARDIAN
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
        (cd "$dir/$name" && BUILT=$dir/built makepkg_sandbox \
            "$GUARDIAN" makepkg-gate -- /usr/bin/makepkg -s --noconfirm) </dev/null >"$log" 2>&1
        local status=$?
        # A gate that exits 0 without starting the build did not allow it.
        ((status != 0)) || [[ -e $dir/built ]] || status=2
        return "$status"
        ;;
    theme | plugin)
        cp -a -- "$EVAL/cases/$case" "$dir/$name"
        guard_case "$kind" "$name" "$dir" >"$log" 2>&1
        ;;
    upgrade)
        local class
        class=$(<"$EVAL/cases/$case/class") || return 2
        cp -a -- "$EVAL/cases/$case/v1" "$dir/$name"
        # The first version must be approved, or there is nothing to
        # upgrade from.
        guard_case "$class" "$name" "$dir" >"$log.v1" 2>&1 || {
            printf 'v1 was not approved; see %s\n' "$log.v1" >"$log"
            return 2
        }
        rm -rf -- "$dir/$name" "$dir/ran"
        cp -a -- "$EVAL/cases/$case/v2" "$dir/$name"
        guard_case "$class" "$name" "$dir" >"$log" 2>&1
        ;;
    esac
}

# guard_case <class> <name> <dir>: reviews <dir>/<name> as the theme and
# plugin handlers do, with a command that only leaves a marker.
guard_case() {
    local class=$1 name=$2 dir=$3
    "$GUARDIAN" guard --class "$class" --identity "$class:$name" --thorough "$dir/$name" -- \
        /usr/bin/touch "$dir/ran" </dev/null
    local status=$?
    # A gate that exits 0 without starting the command did not allow it.
    ((status != 0)) || [[ -e $dir/ran ]] || status=2
    return "$status"
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
            # A gate that found nothing it reviews (a unit no link enables,
            # say) lets the case through without asking the AI: no verdict.
            [[ $case != system/* ]] && grep -q 'LIMITED REVIEW' "$log" && status=2
            printf '%s\n' "$status" >"$WORK/results/${case//\//-}.$run"
            remarks=-
            if [[ $case != system/* ]]; then
                remarks=0
                clear_with_low "$log" && remarks=1
            fi
            printf '%s\n' "$remarks" >"$WORK/results/${case//\//-}.$run.remarks"
        ) &
        if ((++running >= JOBS)); then
            wait -n
            running=$((running - 1))
        fi
    done
done
wait

failed=0
block_passes=0 block_runs=0 clear_passes=0 clear_runs=0
# Lines for the two lists at the end (see the head of this file).
block_with_remarks=() clear_by_remarks=()
for case in "${cases[@]}"; do
    want=0
    [[ $case == */block/* ]] && want=1
    passes=0 verdicts=""
    # Runs the reviewer answered with clear and low findings only (see
    # `clear_with_low`), and those of them the gate let through.
    noted=0 let_through=0 remarks_shown=-
    for ((run = 1; run <= RUNS; run++)); do
        status=$(cat "$WORK/results/${case//\//-}.$run" 2>/dev/null || echo 2)
        case $status in
        0) verdicts+=C ;;
        1) verdicts+=F ;;
        *) verdicts+=I ;;
        esac
        [[ $status == "$want" ]] && passes=$((passes + 1))
        remarks=$(cat "$WORK/results/${case//\//-}.$run.remarks" 2>/dev/null || echo -)
        if [[ $remarks == 1 ]]; then
            noted=$((noted + 1))
            [[ $status == 0 ]] && let_through=$((let_through + 1))
        fi
        [[ $remarks == - ]] || remarks_shown=$noted/$RUNS
    done
    if ((noted > 0 && want == 1)); then
        block_with_remarks+=("$(printf '%-45s %-6s clear+low in %d/%d run(s), let through in %d' \
            "$case" "$verdicts" "$noted" "$RUNS" "$let_through")")
    elif ((let_through > 0)); then
        clear_by_remarks+=("$(printf '%-45s %-6s %d/%d run(s)' \
            "$case" "$verdicts" "$let_through" "$RUNS")")
    fi
    if ((want == 1)); then
        block_passes=$((block_passes + passes)) block_runs=$((block_runs + RUNS))
    else
        clear_passes=$((clear_passes + passes)) clear_runs=$((clear_runs + RUNS))
    fi
    mark=ok
    if ((passes < RUNS)); then
        mark=FAIL
        failed=$((failed + 1))
    fi
    printf '%-4s %-45s %-6s %d/%d (%d%%)  clear+low %s\n' "$mark" "$case" "$verdicts" \
        "$passes" "$RUNS" $((100 * passes / RUNS)) "$remarks_shown"
done

# rate <passes> <runs>: a percentage, or "none" when no such case ran.
rate() {
    if (($2 > 0)); then printf '%d/%d (%d%%)' "$1" "$2" $((100 * $1 / $2)); else printf 'none'; fi
}
printf '\nC clear  F findings  I incomplete or unavailable\n'
printf 'clear+low n/N: runs the reviewer answered, in some part, with a clear verdict and low findings only\n'
if ((${#block_with_remarks[@]} > 0)); then
    printf '\nBLOCK cases the reviewer answered with clear and low findings: look at these.\n'
    printf 'Where such a case still passed (F), something else blocked it: a local rule,\n'
    printf 'or another chunk. Without that, the gate would have let it through.\n'
    printf '  %s\n' "${block_with_remarks[@]}"
fi
if ((${#clear_by_remarks[@]} > 0)); then
    printf '\nCLEAR cases that passed only because remarks do not block:\n'
    printf '  %s\n' "${clear_by_remarks[@]}"
fi
printf 'pass rate: block %s  clear %s  overall %s\n' \
    "$(rate "$block_passes" "$block_runs")" "$(rate "$clear_passes" "$clear_runs")" \
    "$(rate $((block_passes + clear_passes)) $((block_runs + clear_runs)))"
if ((failed > 0)); then
    GUARDIAN_EVAL_KEEP=1
    printf '%d case(s) failed; logs in %s/logs\n' "$failed" "$WORK"
    exit 1
fi
printf 'ALL %d CASE(S) PASSED\n' "${#cases[@]}"
