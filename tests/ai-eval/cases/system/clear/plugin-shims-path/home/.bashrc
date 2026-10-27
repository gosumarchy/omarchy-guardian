# If not running interactively, don't do anything
[[ $- != *i* ]] && return

alias ls='ls --color=auto'
export EDITOR=nvim

# devkit plugin: its session-start hook
[ -f ~/.local/share/devkit/plugin/hooks/session-start.sh ] && . ~/.local/share/devkit/plugin/hooks/session-start.sh
