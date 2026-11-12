#!/usr/bin/env bash
# Image-level checks for the PG18 DHI image: contents, hardening, scanner visibility.
# Usage: tests/test-image.sh <image>
set -euo pipefail

IMAGE="${1:?usage: $0 <image>}"
FAILURES=0
fail() { echo "FAIL: $*"; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $*"; }
check() { local desc="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi; }

run() { docker run --rm --entrypoint "$1" "$IMAGE" "${@:2}"; }
sh_in() { docker run --rm --entrypoint bash "$IMAGE" -c "$1"; }
file_in() { docker run --rm --entrypoint cat "$IMAGE" "$1"; }

test_components() {
    local version
    version="$(run postgres --version)"
    [[ "$version" == *"Percona Server for PostgreSQL"* && "$version" == *" 18."* ]] \
        && pass "postgres is Percona 18 ($version)" || fail "unexpected postgres version: $version"
    check "patroni --version" run patroni --version
    check "pgbackrest version" run pgbackrest version
    check "psql --version" run psql --version
    check "pg_tde_change_key_provider present" sh_in 'command -v pg_tde_change_key_provider'
}

test_hardening() {
    [ "$(docker image inspect -f '{{.Config.User}}' "$IMAGE")" = "70" ] \
        && pass "image USER is 70" || fail "image USER is not 70"
    [ "$(run id -u)" = "70" ] && pass "runs as uid 70" || fail "does not run as uid 70"
    check "no apt/apt-get/dpkg/gosu" sh_in '! command -v apt && ! command -v apt-get && ! command -v dpkg && ! command -v gosu'
    local suid
    suid="$(sh_in 'shopt -s globstar nullglob; for f in /usr/** /etc/** /opt/**; do [ -f "$f" ] && { [ -u "$f" ] || [ -g "$f" ]; } && echo "$f"; done; true')"
    [ -z "$suid" ] && pass "no setuid/setgid files" || fail "setuid/setgid files: $suid"
}

test_shared_libraries() {
    local missing
    missing="$(sh_in 'shopt -s nullglob; for f in /usr/lib/postgresql/18/bin/* /usr/lib/postgresql/18/lib/*.so /usr/bin/pgbackrest; do
        out="$(/usr/lib/*-linux-gnu/ld-linux*.so.* --list "$f" 2>/dev/null || true)"
        case "$out" in *"not found"*) echo "$f";; esac; done')"
    [ -z "$missing" ] && pass "no unresolved shared libraries" || fail "unresolved libraries in: $missing"
}

test_package_origins() {
    local report
    report="$(file_in /usr/share/percona/package-origins.tsv)"
    [ -n "$report" ] && pass "origin report present" || { fail "origin report missing"; return; }
    awk -F'\t' '$3 !~ /^(dhi|percona|debian-allowlist)$/' <<< "$report" | grep -q . \
        && fail "origin report has unknown origins" || pass "all origins dhi|percona|debian-allowlist"
    grep -qP '^percona-postgresql-18\t[^\t]+\tpercona$' <<< "$report" \
        && pass "percona-postgresql-18 from percona" || fail "percona-postgresql-18 not from percona"
    # Interpreters exist in both DHI and Debian; the DHI build must win (DHI names it python-3.13)
    local pkg
    for pkg in python-3.13 perl-base; do
        grep -qP "^${pkg//./\\.}\t[^\t]+\tdhi\$" <<< "$report" \
            && pass "$pkg from dhi" || fail "$pkg missing or not from dhi"
    done
}

test_scanner_visibility() {
    local trivy_pkgs grype_pkgs pkg
    trivy_pkgs="$(trivy image -q --list-all-pkgs -f json "$IMAGE")"
    # grype's JSON lists only matches; its CycloneDX output carries the full inventory
    grype_pkgs="$(grype -q -o cyclonedx-json "docker:$IMAGE" | tr -d ' \n')"
    for pkg in percona-postgresql-18 percona-patroni percona-pgbackrest; do
        grep -q "\"Name\": \"$pkg\"" <<< "$trivy_pkgs" && pass "trivy sees $pkg" || fail "trivy does not see $pkg"
        grep -q "\"name\":\"$pkg\"" <<< "$grype_pkgs" \
            && pass "grype sees $pkg" || fail "grype does not see $pkg"
    done
}

test_components
test_hardening
test_shared_libraries
test_package_origins
test_scanner_visibility

[ "$FAILURES" -eq 0 ] && echo "ALL PASSED" || { echo "$FAILURES FAILURE(S)"; exit 1; }
