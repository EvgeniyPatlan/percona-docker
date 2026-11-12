#!/usr/bin/env bash
# Configure apt in a DHI debian-base -dev builder stage: Percona repository
# (signature key verified by fingerprint) and the source-priority policy.
set -euo pipefail

PERCONA_KEY_FPR="${PERCONA_KEY_FPR:-4D1BB29D63D98E422B2113B19334A25F8507EFA5}"
PPG_REPO_NAME="${PPG_REPO_NAME:-ppg-18}"
PPG_REPO="${PPG_REPO:-release}"
SUITE="${SUITE:-trixie}"
HERE="$(cd "$(dirname "$0")" && pwd)"

case "$PPG_REPO" in
    release) component=main ;;
    testing|experimental) component="$PPG_REPO" ;;
    *) echo "ERROR: unsupported PPG_REPO '$PPG_REPO' (release|testing|experimental)" >&2; exit 1 ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl gnupg >/dev/null

keyring=/usr/share/keyrings/percona-archive-keyring.gpg
tmpkey="$(mktemp)"
curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x${PERCONA_KEY_FPR}" -o "$tmpkey"
actual_fpr="$(gpg --show-keys --with-colons "$tmpkey" | awk -F: '/^fpr:/ {print $10; exit}')"
if [ "$actual_fpr" != "$PERCONA_KEY_FPR" ]; then
    echo "ERROR: Percona key fingerprint mismatch: got '$actual_fpr', expected '$PERCONA_KEY_FPR'" >&2
    exit 1
fi
gpg --dearmor < "$tmpkey" > "$keyring"
rm -f "$tmpkey"

echo "deb [signed-by=${keyring}] https://repo.percona.com/${PPG_REPO_NAME}/apt ${SUITE} ${component}" \
    > /etc/apt/sources.list.d/percona-${PPG_REPO_NAME}.list
install -m 0644 "$HERE/apt-preferences" /etc/apt/preferences.d/dhi-source-policy
apt-get update -qq
