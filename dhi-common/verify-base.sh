#!/usr/bin/env bash
# Verify the Docker Hardened Images (DHI) base images used by the DHI-based images:
# lists the attestations attached to the pinned digest and cryptographically verifies
# each of them with cosign against Docker's published DHI public key.
#
# Usage: verify-base.sh [image-ref@sha256:digest ...]
#   With no arguments, DHI_RUNTIME and DHI_BUILDER are read from
#   percona-distribution-postgresql-18-dhi/Dockerfile.
#
# Method (docs.docker.com/dhi/how-to/verify): attestations are OCI referrers of the
# per-platform manifest; each in-toto attestation manifest is verified with
#   cosign verify --key <dhi keyring public key> --insecure-ignore-tlog=true <repo>@<attestation digest>
# (DHI attestations are not guaranteed to be in the public Rekor log, so the transparency
# log check is skipped; the signature is still checked against Docker's key.)
#
# Result column: VERIFIED = cosign signature verification succeeded; FAILED = it was
# attempted and failed (exit 1); PRESENT = listed only, no signature check performed.
#
# Env: COSIGN_IMAGE, DHI_PUBKEY_URL, PLATFORM (default linux/amd64), DOCKER_CONFIG_DIR.
# Requires: docker (logged in to dhi.io), curl, jq.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COSIGN_IMAGE="${COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign:v3.1.4}"
DHI_PUBKEY_URL="${DHI_PUBKEY_URL:-https://registry.scout.docker.com/keyring/dhi/latest.pub}"
PLATFORM="${PLATFORM:-linux/amd64}"
DOCKER_CONFIG_DIR="${DOCKER_CONFIG_DIR:-${DOCKER_CONFIG:-$HOME/.docker}}"

die() { echo "ERROR: $*" >&2; exit 2; }
for tool in docker curl jq; do command -v "$tool" >/dev/null || die "$tool is required"; done
[ -f "$DOCKER_CONFIG_DIR/config.json" ] || die "no docker config at $DOCKER_CONFIG_DIR (docker login dhi.io first)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

curl -fsSL "$DHI_PUBKEY_URL" -o "$WORK/dhi.pub" || die "cannot download DHI public key from $DHI_PUBKEY_URL"
head -1 "$WORK/dhi.pub" | grep -q 'BEGIN PUBLIC KEY' || die "downloaded DHI key is not a PEM public key"
chmod 644 "$WORK/dhi.pub"

cosign() {
    docker run --rm --user "$(id -u):$(id -g)" -e DOCKER_CONFIG=/dc -v "$DOCKER_CONFIG_DIR:/dc:ro" -v "$WORK/dhi.pub:/dhi.pub:ro" \
        "$COSIGN_IMAGE" "$@"
}

refs=("$@")
if [ "${#refs[@]}" -eq 0 ]; then
    dockerfile="$HERE/../percona-distribution-postgresql-18-dhi/Dockerfile"
    [ -f "$dockerfile" ] || die "no refs given and $dockerfile not found"
    for arg in DHI_RUNTIME DHI_BUILDER; do
        ref="$(sed -n "s/^ARG $arg=//p" "$dockerfile" | head -1)"
        [ -n "$ref" ] || die "ARG $arg not found in $dockerfile"
        refs+=("$ref")
    done
fi

FAILED=0
NOTHING=0
printf '| Image | Check | Subject | Result |\n|---|---|---|---|\n'
row() { printf '| %s | %s | %s | %s |\n' "$1" "$2" "$3" "$4"; }

verify_ref() {
    local ref="$1" repo digest index_json platform_digest tree art_digest manifest atype
    [[ "$ref" == *@sha256:* ]] || die "$ref must be pinned by digest (name[:tag]@sha256:...)"
    repo="${ref%%@*}"; repo="${repo%%:*}"; digest="${ref##*@}"

    index_json="$(docker buildx imagetools inspect --raw "$ref")" || die "cannot inspect $ref"
    platform_digest="$(jq -r --arg p "$PLATFORM" '
        if .manifests then (.manifests[] | select((.platform.os + "/" + .platform.architecture) == $p) | .digest)
        else empty end' <<<"$index_json")"
    [ -n "$platform_digest" ] || die "no $PLATFORM manifest in $ref"

    # signature artifact(s) attached to the index: listed only, cosign cannot verify them via tag lookup
    tree="$(cosign tree "$ref")" || die "cosign tree failed for $ref"
    if grep -q 'cosign.artifact.sig' <<<"$tree"; then
        row "$ref" "cosign signature artifact on index" "$digest" "PRESENT (not verified)"
    fi

    tree="$(cosign tree "$repo@$platform_digest")" || die "cosign tree failed for $repo@$platform_digest"
    # collect in-toto attestation referrers, then verify them in parallel (each cosign run is slow)
    local count=0 pids=() i
    local -a digests=() ptypes=()
    while read -r art; do
        art_digest="${art##*@}"
        manifest="$(docker buildx imagetools inspect --raw "$repo@$art_digest")" \
            || die "cannot read attestation manifest $repo@$art_digest"
        atype="$(jq -r '.artifactType // ""' <<<"$manifest")"
        [ "$atype" = "application/vnd.in-toto+json" ] || continue
        digests+=("$art_digest")
        ptypes+=("$(jq -r '.annotations["in-toto.io/predicate-type"] // "unknown"' <<<"$manifest")")
    done < <(grep -o 'referrer: .*' <<<"$tree" | sed 's/^referrer: //')
    count="${#digests[@]}"
    for i in "${!digests[@]}"; do
        cosign verify --key /dhi.pub --insecure-ignore-tlog=true "$repo@${digests[$i]}" >"$WORK/out.$i" 2>&1 &
        pids+=($!)
    done
    for i in "${!digests[@]}"; do
        if wait "${pids[$i]}"; then
            row "$ref" "attestation ${ptypes[$i]}" "${digests[$i]:0:19}" "VERIFIED (cosign, DHI key)"
        else
            row "$ref" "attestation ${ptypes[$i]}" "${digests[$i]:0:19}" "FAILED"
            sed 's/^/    /' "$WORK/out.$i" >&2
            FAILED=$((FAILED + 1))
        fi
    done

    if [ "$count" -eq 0 ]; then
        row "$ref" "attestations" "$platform_digest" "NONE FOUND"
        NOTHING=$((NOTHING + 1))
    fi
}

for ref in "${refs[@]}"; do verify_ref "$ref"; done

echo
if [ "$FAILED" -gt 0 ]; then echo "RESULT: $FAILED signature verification(s) FAILED"; exit 1; fi
if [ "$NOTHING" -gt 0 ]; then echo "RESULT: no attestations found for $NOTHING image(s); nothing verified"; exit 3; fi
echo "RESULT: all attestations verified with cosign against the DHI public key"
