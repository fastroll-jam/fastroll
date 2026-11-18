#!/usr/bin/env bash
# Prints the CHANGELOG.md entry of a release, which the release workflow publishes as its notes.
# Fails when the entry is missing, lists no changes, or names another Graypaper version.
#
# e.g. ./scripts/extract-release-notes.sh 0.2.0 0.8.0

set -euo pipefail

usage="Usage: extract-release-notes.sh <version> <graypaper-version> [changelog-path]"
version="${1:?${usage}}"
graypaper_version="${2:?${usage}}"
changelog_path="${3:-CHANGELOG.md}"

fail() {
    echo "extract-release-notes: $*" >&2
    exit 1
}

release_notes="$(awk -v heading="## [${version}] - " '
    /^## / {
        release_date = substr($0, length(heading) + 1)
        in_entry = (index($0, heading) == 1 && release_date ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/)
        next
    }
    /^\[[^]]+\]: / { in_entry = 0 }
    in_entry { print }
' "${changelog_path}" | sed '/./,$!d')"

[ -n "${release_notes}" ] || fail "${changelog_path} has no dated entry for ${version}"
grep -Fxq "Graypaper: ${graypaper_version}" <<<"${release_notes}" \
    || fail "the entry for ${version} does not name Graypaper ${graypaper_version}"
grep -q '^- ' <<<"${release_notes}" || fail "the entry for ${version} lists no changes"

printf '%s\n' "${release_notes}"
