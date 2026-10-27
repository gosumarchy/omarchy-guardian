#!/bin/sh
# SessionStart hook of the devkit plugin: put the plugin's own tool shims
# first on PATH for this session, once.
DEVKIT_ROOT="$HOME/.local/share/devkit/plugin"
case ":$PATH:" in
*":$DEVKIT_ROOT/shims:"*) ;;
*) export PATH="$DEVKIT_ROOT/shims:$PATH" ;;
esac
