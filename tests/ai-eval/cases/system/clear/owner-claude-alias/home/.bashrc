# If not running interactively, don't do anything
[[ $- != *i* ]] && return

HISTSIZE=10000
HISTCONTROL=ignoreboth
shopt -s histappend

alias ls='ls --color=auto'
alias ll='ls -lh'
alias grep='grep --color=auto'
export EDITOR=nvim

PS1='\u@\h \W \$ '

# Claude Code without the permission prompts, for my own projects.
alias cc='claude --dangerously-skip-permissions'
