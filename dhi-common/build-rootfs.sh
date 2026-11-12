#!/usr/bin/env bash
# Install Debian packages into a DHI runtime rootfs without a package manager.
#
# The rootfs must be pre-seeded with the runtime base image (COPY --from=runtime / /rootfs).
# Dependencies are resolved against the rootfs' own dpkg database, so only packages
# missing from the runtime base are added. Every added package must come from
# dhi.io or repo.percona.com, or be listed in the allowlist (deb.debian.org).
# Package metadata is written to the rootfs dpkg database so scanners can see it.
set -euo pipefail

usage() {
    echo "Usage: $0 --packages FILE --allowlist FILE --rootfs DIR --report FILE" >&2
    exit 2
}

PACKAGES_FILE="" ALLOWLIST_FILE="" ROOTFS="" REPORT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --packages) PACKAGES_FILE="$2"; shift 2 ;;
        --allowlist) ALLOWLIST_FILE="$2"; shift 2 ;;
        --rootfs) ROOTFS="$2"; shift 2 ;;
        --report) REPORT="$2"; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$PACKAGES_FILE" ] && [ -n "$ALLOWLIST_FILE" ] && [ -n "$ROOTFS" ] && [ -n "$REPORT" ] || usage
[ -f "$ROOTFS/var/lib/dpkg/status" ] || { echo "ERROR: $ROOTFS is not a seeded rootfs" >&2; exit 1; }

STATUS="$ROOTFS/var/lib/dpkg/status"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

read_list() { grep -vE '^[[:space:]]*(#|$)' "$1" | awk '{print $1}'; }

resolve_packages() {
    mapfile -t wanted < <(read_list "$PACKAGES_FILE")
    [ "${#wanted[@]}" -gt 0 ] || { echo "ERROR: no packages in $PACKAGES_FILE" >&2; exit 1; }
    apt-get -o Dir::State::status="$STATUS" install -s --no-install-recommends "${wanted[@]}" \
        > "$WORK/simulate.log" || { cat "$WORK/simulate.log" >&2; exit 1; }
    awk '/^Inst /{print $2}' "$WORK/simulate.log" > "$WORK/resolved"
}

classify_origin() {
    case "$1" in
        *://dhi.io/*) echo dhi ;;
        *://repo.percona.com/*) echo percona ;;
        *://deb.debian.org/*) echo debian ;;
        *) echo unknown ;;
    esac
}

check_policy() {
    local violations=0 name version url file origin allowed
    # Allowlist lines: "<package> [<version>]"; a version, when given, must match (ignoring +bN binNMU suffix).
    grep -vE '^[[:space:]]*(#|$)' "$ALLOWLIST_FILE" | awk '{print $1, ($2 == "" ? "*" : $2)}' > "$WORK/allowlist"
    # shellcheck disable=SC2046
    apt-get -o Dir::State::status="$STATUS" --print-uris download $(cat "$WORK/resolved") \
        | tr -d "'" > "$WORK/uris"
    : > "$WORK/origins"
    while read -r url file _; do
        name="${file%%_*}"
        version="${file#*_}"; version="${version%_*}"; version="${version//%3a/:}"
        origin="$(classify_origin "$url")"
        if [ "$origin" = debian ]; then
            allowed="$(awk -v n="$name" '$1 == n {print $2; exit}' "$WORK/allowlist")"
            if [ -z "$allowed" ]; then
                echo "POLICY VIOLATION: $name from deb.debian.org (not in allowlist)" >&2
                violations=$((violations + 1))
            # binNMU suffixes (+bN) differ per architecture, so they are not part of the pin
            elif [ "$allowed" != "*" ] && [ "${allowed%+b[0-9]*}" != "${version%+b[0-9]*}" ]; then
                echo "POLICY VIOLATION: $name $version from deb.debian.org (allowlist pins $allowed)" >&2
                violations=$((violations + 1))
            else
                origin=debian-allowlist
            fi
        elif [ "$origin" = unknown ]; then
            echo "POLICY VIOLATION: $name from unknown source $url" >&2
            violations=$((violations + 1))
        fi
        printf '%s\t%s\n' "$name" "$origin" >> "$WORK/origins"
    done < "$WORK/uris"
    [ "$violations" -eq 0 ] || { echo "ERROR: $violations package source policy violation(s)" >&2; exit 1; }
}

install_debs() {
    local deb name
    mkdir -p "$WORK/debs" "$ROOTFS/var/lib/dpkg/info"
    # shellcheck disable=SC2046
    (cd "$WORK/debs" && apt-get -o APT::Sandbox::User=root download $(cat "$WORK/resolved") >/dev/null)
    for deb in "$WORK"/debs/*.deb; do
        name="$(dpkg-deb -f "$deb" Package)"
        # --keep-directory-symlink preserves merged-usr symlinks (/bin -> usr/bin, ...)
        dpkg-deb --fsys-tarfile "$deb" | tar -x --keep-directory-symlink -C "$ROOTFS"
        dpkg-deb --fsys-tarfile "$deb" | tar -t | sed -e 's#^\./#/#' -e 's#/$##' -e 's#^$#/.#' \
            > "$ROOTFS/var/lib/dpkg/info/${name}.list"
        { echo; dpkg-deb -f "$deb" | sed '/^Package:/a Status: install ok installed'; } >> "$STATUS"
        printf '%s\t%s\t%s\n' "$name" "$(dpkg-deb -f "$deb" Version)" \
            "$(awk -F'\t' -v n="$name" '$1==n {print $2; exit}' "$WORK/origins")" >> "$WORK/report"
    done
}

harden_rootfs() {
    rm -rf "$ROOTFS"/usr/share/man/* "$ROOTFS"/usr/share/info/* "$ROOTFS"/usr/share/lintian
    find "$ROOTFS/usr/share/doc" -mindepth 2 ! -name copyright ! -type d -delete 2>/dev/null || true
    rm -f "$ROOTFS"/usr/bin/apt* "$ROOTFS"/usr/bin/dpkg* "$ROOTFS"/usr/sbin/dpkg*
    find "$ROOTFS" -xdev -type f -perm /6000 -exec chmod ug-s {} +
    ldconfig -r "$ROOTFS"
}

resolve_packages
check_policy
: > "$WORK/report"
install_debs
harden_rootfs
mkdir -p "$(dirname "$REPORT")"
sort "$WORK/report" > "$REPORT"
echo "Installed $(wc -l < "$REPORT") package(s) into $ROOTFS:"
awk -F'\t' '{c[$3]++} END {for (o in c) printf "  %-17s %d\n", o, c[o]}' "$REPORT"
