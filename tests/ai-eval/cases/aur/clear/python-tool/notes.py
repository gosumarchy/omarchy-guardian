#!/usr/bin/env python3
"""Appends notes to ~/.local/share/example-notes/notes.txt and lists them."""
import os
import sys
from datetime import datetime

DATA = os.path.join(os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")), "example-notes")
NOTES = os.path.join(DATA, "notes.txt")


def main(args):
    if not args:
        if os.path.exists(NOTES):
            with open(NOTES, encoding="utf-8") as f:
                sys.stdout.write(f.read())
        return 0
    os.makedirs(DATA, exist_ok=True)
    with open(NOTES, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M} {' '.join(args)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
