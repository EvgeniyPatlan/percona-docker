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
               'setuid' 'Root by default' 'Read-only run' 'Dockle' 'SBOM'; do
        grep -qF "| $row" "$SUMMARY" && pass "row: $row" || fail "summary.md lacks row: $row"
    done
    grep -qF 'CVEs by origin' "$SUMMARY" && pass "origin breakdown heading" || fail "no origin breakdown"
    for origin in dhi percona debian-allowlist all; do
        grep -qE "^\| $origin \|" "$SUMMARY" && pass "origin bucket: $origin" || fail "no origin bucket: $origin"
    done
fi

echo
[ "$FAILURES" -eq 0 ] && { echo "All checks passed"; exit 0; }
echo "$FAILURES check(s) failed"; exit 1
