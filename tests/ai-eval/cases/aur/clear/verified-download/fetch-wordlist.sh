#!/bin/sh
# Downloads the word list of one release and checks it against the checksum
# pinned here before anything uses it. The file is data: it is never run.
set -eu

version=$1
output=$2
expected=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --output "$output.part" "https://example.com/wordlist/releases/$version/words.txt"

actual=$(sha256sum "$output.part" | cut -d ' ' -f 1)
if [ "$actual" != "$expected" ]; then
    rm -f "$output.part"
    echo "checksum mismatch for words.txt: got $actual" >&2
    exit 1
fi
mv "$output.part" "$output"
