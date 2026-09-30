# Sourced from the user's interactive Bash rc by the Guardian installer.
_omarchy_guardian_help_requested() {
    local arg
    for arg in "$@"; do
        [[ $arg == --help || $arg == -h ]] && return 0
    done
    return 1
}

omarchy() {
    if [[ ${1-} == theme && ${2-} == install ]]; then
        if _omarchy_guardian_help_requested "$@"; then
            command /usr/share/omarchy/bin/omarchy "$@"
            return
        fi
        shift 2
        /usr/lib/omarchy-guardian/guardian-theme install "$@"
    elif [[ ${1-} == theme && ${2-} == update ]]; then
        if _omarchy_guardian_help_requested "$@"; then
            command /usr/share/omarchy/bin/omarchy "$@"
            return
        fi
        shift 2
        /usr/lib/omarchy-guardian/guardian-theme update "$@"
    elif [[ ${1-} == plugin && ( ${2-} == add || ${2-} == install || ${2-} == update ) ]]; then
        if _omarchy_guardian_help_requested "$@"; then
            command /usr/share/omarchy/bin/omarchy "$@"
            return
        fi
        local action=$2
        shift 2
        /usr/lib/omarchy-guardian/guardian-plugin "$action" "$@"
    else
        command /usr/share/omarchy/bin/omarchy "$@"
    fi
}

omarchy-theme-install() {
    if _omarchy_guardian_help_requested "$@"; then
        command /usr/share/omarchy/bin/omarchy theme install --help
        return
    fi
    /usr/lib/omarchy-guardian/guardian-theme install "$@"
}

omarchy-theme-update() {
    if _omarchy_guardian_help_requested "$@"; then
        command /usr/share/omarchy/bin/omarchy theme update --help
        return
    fi
    /usr/lib/omarchy-guardian/guardian-theme update "$@"
}

omarchy-plugin-add() {
    if _omarchy_guardian_help_requested "$@"; then
        command /usr/share/omarchy/bin/omarchy-plugin-add --help
        return
    fi
    /usr/lib/omarchy-guardian/guardian-plugin add "$@"
}

omarchy-plugin-update() {
    if _omarchy_guardian_help_requested "$@"; then
        command /usr/share/omarchy/bin/omarchy-plugin-update --help
        return
    fi
    /usr/lib/omarchy-guardian/guardian-plugin update "$@"
}
