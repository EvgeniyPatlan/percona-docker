#!/usr/bin/env bash
# Tests for dhi-common/build-rootfs.sh. Requires docker buildx, trivy and access to dhi.io.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
COMMON="$(dirname "$HERE")"
TAG="dhi-common-test:jq"
FAILURES=0

fail() { echo "FAIL: $*"; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $*"; }

build() {
    docker buildx build --load --progress plain \
        --build-context dhi-common="$COMMON" -f "$HERE/Dockerfile.test" "$@" "$HERE"
}

run_in() { docker run --rm --entrypoint "$1" "$TAG" "${@:2}"; }
# The runtime image has no grep: read files with cat and match on the host.
file_in() { docker run --rm --entrypoint cat "$TAG" "$1"; }

test_installs_package_with_metadata() {
    build -t "$TAG" > ${TMPDIR:-/tmp}/dhi-common-test-build.log 2>&1 || { fail "build failed (see ${TMPDIR:-/tmp}/dhi-common-test-build.log)"; return; }
    run_in jq --version >/dev/null && pass "jq runs" || fail "jq does not run"
    file_in /var/lib/dpkg/status | grep -qx "Package: jq" \
        && pass "dpkg status lists jq" || fail "dpkg status missing jq"
    run_in bash -c 'test -s /var/lib/dpkg/info/jq.list' \
        && pass "jq.list present" || fail "jq.list missing"
    file_in /usr/share/percona/package-origins.tsv | grep -qP "^jq\t[^\t]+\t(dhi|percona|debian-allowlist)$" \
        && pass "origin report has jq" || fail "origin report missing jq"
    run_in bash -c 'test -L /bin && test -L /lib' \
        && pass "merged-usr symlinks kept" || fail "merged-usr symlinks broken"
    run_in bash -c '! command -v dpkg && ! command -v apt-get' >/dev/null \
        && pass "no package manager" || fail "package manager present"
    local inventory
    inventory="$(trivy image -q --list-all-pkgs -f json "$TAG")"
    if grep -q '"Name": "jq"' <<< "$inventory"; then
        pass "trivy sees jq"
    else
        fail "trivy does not see jq"
    fi
}

test_rejects_debian_package_not_on_allowlist() {
    # python3-yaml exists only in upstream Debian (verified 2026-11-12).
    if build -t dhi-common-test:violation --build-arg PACKAGES=python3-yaml --build-arg ALLOWLIST=none \
        > ${TMPDIR:-/tmp}/dhi-common-test-violation.log 2>&1; then
        fail "build with non-allowlisted Debian package succeeded"
    elif grep -q 'POLICY VIOLATION: python3-yaml from deb.debian.org' ${TMPDIR:-/tmp}/dhi-common-test-violation.log; then
        pass "policy violation reported"
    else
        fail "build failed for another reason (see ${TMPDIR:-/tmp}/dhi-common-test-violation.log)"
    fi
}

test_installs_package_with_metadata
test_rejects_debian_package_not_on_allowlist

[ "$FAILURES" -eq 0 ] && echo "ALL PASSED" || { echo "$FAILURES FAILURE(S)"; exit 1; }
