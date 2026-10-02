#!/bin/bash
set -euo pipefail

interceptor=/usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh
bashrc="$HOME/.bashrc"
source_line="[[ -r $interceptor ]] && source $interceptor"
marker="# Omarchy Guardian theme command interception"

[[ -r $interceptor ]] || {
    printf 'Guardian interceptor is not installed: %s\n' "$interceptor" >&2
    exit 2
}

touch "$bashrc"
# The line that loads it, not the marker: a marker left behind, or a line
# commented out, loads nothing.
if ! grep -Fxq "$source_line" "$bashrc"; then
    {
        printf '\n%s\n' "$marker"
        printf '%s\n' "$source_line"
    } >>"$bashrc"
fi

printf 'Enabled Guardian interception for omarchy theme install/update in %s. Open a new Bash shell to use it.\n' "$bashrc"
