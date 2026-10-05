#!/bin/bash
# Checks the links of the documentation, without the network:
#   - every relative link in README.md, SECURITY.md and docs/*.md names a
#     file that exists;
#   - every #anchor matches a heading of the file it points into, by the
#     rule GitHub makes heading anchors with (so a link to a section of the
#     old single-page README, which no page has any more, fails);
#   - every page under docs/ is linked from the README's "Documentation"
#     section.
# Links and headings inside fenced code blocks are not read. Links to other
# sites are not followed.
#
# Usage: bash tests/docs-links.sh
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"

pages=(README.md SECURITY.md docs/*.md)
failures=0

fail() {
    printf 'FAIL  %s\n' "$*" >&2
    failures=$((failures + 1))
}

# The anchors of a page's headings, one a line, as GitHub makes them: lower
# case, everything but letters, digits, blanks, "-" and "_" removed, blanks
# to "-", and "-1", "-2" ... added to a heading that repeats.
anchors() {
    awk '
        /^[[:space:]]*```/ { fence = !fence; next }
        fence { next }
        /^#{1,6} / {
            text = tolower($0)
            sub(/^#+ +/, "", text)
            sub(/[[:space:]]+$/, "", text)
            gsub(/[^a-z0-9 _-]/, "", text)
            gsub(/ /, "-", text)
            if (text in seen) {
                print text "-" seen[text]++
            } else {
                seen[text] = 1
                print text
            }
        }
    ' "$1"
}

# The targets of a page's links, as "line<TAB>target". With a second
# argument, only those under the heading of that name.
links() {
    awk -v section="${2:-}" '
        /^[[:space:]]*```/ { fence = !fence; next }
        fence { next }
        /^#{1,6} / {
            if (section != "") {
                inside = ($0 == "## " section)
            }
            next
        }
        section != "" && !inside { next }
        {
            line = $0
            while (match(line, /\]\([^)[:space:]]+\)/)) {
                print NR "\t" substr(line, RSTART + 2, RLENGTH - 3)
                line = substr(line, RSTART + RLENGTH)
            }
        }
    ' "$1"
}

for page in "${pages[@]}"; do
    [[ -f $page ]] || {
        fail "$page is missing"
        continue
    }
    dir=$(dirname -- "$page")
    while IFS=$'\t' read -r line target; do
        case $target in
            http://* | https://* | mailto:*) continue ;;
        esac
        file=${target%%#*}
        anchor=''
        [[ $target == *'#'* ]] && anchor=${target#*#}
        if [[ -z $file ]]; then
            dest=$page
        else
            dest=$dir/$file
        fi
        if [[ ! -e $dest ]]; then
            fail "$page:$line: ($target) names a file that does not exist"
            continue
        fi
        [[ -n $anchor ]] || continue
        if [[ $dest != *.md ]]; then
            fail "$page:$line: ($target) has an anchor into a file that is not Markdown"
            continue
        fi
        if ! anchors "$dest" | grep -qxF -- "$anchor"; then
            fail "$page:$line: ($target) matches no heading of $dest"
        fi
    done < <(links "$page")
done

index=$(links README.md Documentation | cut -f2)
if [[ -z $index ]]; then
    fail "README.md has no links under a \"## Documentation\" heading"
fi
for page in docs/*.md; do
    if ! grep -qxF -- "$page" <<<"$index"; then
        fail "$page is not listed under \"## Documentation\" in README.md"
    fi
done

if ((failures > 0)); then
    printf '%d problem(s) in the documentation links\n' "$failures" >&2
    exit 1
fi
printf 'ok    %d pages, links and anchors checked\n' "${#pages[@]}"
