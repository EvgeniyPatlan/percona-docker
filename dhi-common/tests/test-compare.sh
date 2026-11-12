#!/usr/bin/env bash
# Runs compare.sh against a baseline and a DHI image and asserts on its outputs.
# Usage: tests/test-compare.sh [baseline-image] [dhi-image] [outdir]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE="${1:-percona/percona-distribution-postgresql:18.6.1-4}"
DHI="${2:-percona-distribution-postgresql:18-dhi}"
OUT="${3:-$(mktemp -d)}"
FAILURES=0
fail() { echo "FAIL: $*"; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $*"; }

# row_cell <summary> <metric> <column 1=baseline 2=dhi>
row_cell() {
    local line f
    line="$(grep -F "| $2 |" "$1" | head -1)"
    IFS='|' read -ra f <<<"$line"
    echo "${f[$3 + 1]# }" | sed 's/ *$//'
}

check_cells() {
    local summary="$1" col label cell
    for col in 1 2; do
        label="$([ "$col" = 1 ] && echo baseline || echo dhi)"
        for pair in 'CVEs (trivy)|^[0-9]+ \(C [0-9]+, H [0-9]+, M [0-9]+, L [0-9]+\)$' \
                    'CVEs (grype)|^[0-9]+ \(C [0-9]+, H [0-9]+, M [0-9]+, L [0-9]+\)$' \
                    'CVEs (trivy, fixable)|^[0-9]+ \(C ' 'CVEs (grype, fixable)|^[0-9]+ \(C ' \
                    'Packages|^[1-9][0-9]*$' 'setuid|^[0-9]+$' 'Size|^[0-9]+ MiB' \
                    'Root by default|^(yes|no) ' 'Read-only run|^(works|fails)' \
                    'Dockle|^fatal [0-9]+, warn [0-9]+' 'Scanner visibility|^ok: ' \
                    'Package manager|^(yes|no)' 'Shells|^(yes|no)'; do
            cell="$(row_cell "$summary" "${pair%%|*}" "$col")"
            [[ "$cell" =~ ${pair#*|} ]] && pass "$label ${pair%%|*}: $cell" || fail "$label ${pair%%|*} cell malformed: '$cell'"
        done
    done
}

# Scanner visibility must fail loudly: require a package that does not exist.
negative_visibility() {
    local neg_out msg
    neg_out="$(mktemp -d)"
    if msg="$(REQUIRED_PKGS_BASELINE='no-such-package-xyz' "$HERE/../compare.sh" "$BASELINE" "$DHI" "$neg_out" 2>&1)"; then
        fail "compare.sh succeeded although a required package is not visible"
    elif [[ "$msg" == *"SCANNER VISIBILITY"* ]]; then
        pass "compare.sh fails when a required package is invisible"
    else
        fail "compare.sh failed without a visibility message: $msg"
    fi
    rm -rf "$neg_out"
}

if "$HERE/../compare.sh" "$BASELINE" "$DHI" "$OUT"; then
    pass "compare.sh exits 0"
else
    fail "compare.sh exited non-zero"
fi

for pattern in 'trivy-*.json' 'grype-*.json' 'sbom-*.spdx.json' 'sbom-*.cdx.json' 'dockle-*.json'; do
    n="$(find "$OUT" -maxdepth 1 -name "$pattern" -size +0c | wc -l)"
    [ "$n" -ge 2 ] && pass "$pattern: $n files" || fail "$pattern: expected 2 non-empty files, found $n"
done

SUMMARY="$OUT/summary.md"
if [ ! -s "$SUMMARY" ]; then
    fail "summary.md missing or empty"
else
    for row in 'Size' 'Packages' 'CVEs (trivy)' 'CVEs (grype)' 'Package manager' 'Shells' \
               'setuid' 'Root by default' 'Read-only run' 'Dockle' 'SBOM' 'Scanner visibility'; do
        grep -qF "| $row" "$SUMMARY" && pass "row: $row" || fail "summary.md lacks row: $row"
    done
    # cells must be non-empty and have the expected shape (not just a row label)
    check_cells "$SUMMARY"
    tsv_line="$(grep -P '^percona-postgresql-18\t' "$OUT/origins-dhi.tsv" || true)"
    [ -n "$tsv_line" ] && pass "origins-dhi.tsv has percona-postgresql-18" || fail "origins-dhi.tsv lacks percona-postgresql-18"
    grep -qF 'CVEs by origin' "$SUMMARY" && pass "origin breakdown heading" || fail "no origin breakdown"
    for origin in dhi percona debian-allowlist all; do
        grep -qE "^\| $origin \|" "$SUMMARY" && pass "origin bucket: $origin" || fail "no origin bucket: $origin"
    done
fi

negative_visibility

echo
[ "$FAILURES" -eq 0 ] && { echo "All checks passed"; exit 0; }
echo "$FAILURES check(s) failed"; exit 1
