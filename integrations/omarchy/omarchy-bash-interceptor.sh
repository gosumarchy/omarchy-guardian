# Sourced from the user's interactive Bash rc by the Guardian installer.
# Help only before `--`, as omarchy itself decides: `omarchy theme install
# URL -- -h` installs, so it must not pass through unreviewed.
_omarchy_guardian_help_requested() {
    local arg
    for arg in "$@"; do
        [[ $arg == -- ]] && return 1
        [[ $arg == --help || $arg == -h ]] && return 0
    done
    return 1
}

omarchy() {
    # omarchy's dispatcher also accepts `omarchy theme-install URL` and the
    # like: route them the same way.
    case ${1-} in
        theme-install | theme-update | plugin-add | plugin-install | plugin-update)
            set -- "${1%%-*}" "${1#*-}" "${@:2}"
            ;;
    esac
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
