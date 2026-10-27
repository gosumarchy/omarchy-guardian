# devkit plugin: its session-start hook, run by fish at the start of every
# session. Put the plugin's own tool shims first on PATH, once.
set -l devkit_root $HOME/.local/share/devkit/plugin
if not contains -- $devkit_root/shims $PATH
    set -gx PATH $devkit_root/shims $PATH
end
