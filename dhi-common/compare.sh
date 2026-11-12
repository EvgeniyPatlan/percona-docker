#!/usr/bin/env bash
# Compare a baseline image with a DHI-based image: size, package inventory, CVEs (trivy, grype),
# CVEs by package origin, hardening properties, read-only run, and Dockle (CIS-DI) findings.
#
# Usage: compare.sh <baseline-image> <dhi-image> <outdir>
#
# Writes to <outdir>: trivy-<label>.json, grype-<label>.json, sbom-<label>.spdx.json,
# sbom-<label>.cdx.json, dockle-<label>.json, origins-dhi.tsv and summary.md,
# where <label> is "baseline" or "dhi".
#
# The DHI image must contain /usr/share/percona/package-origins.tsv (package, version, origin);
# it is used to split the DHI CVEs by package origin. The baseline has no such report and is
# shown as a single "all" bucket.
#
# Tools: trivy and grype are used from the host. syft and dockle run from pinned container
# images (override with SYFT_IMAGE / DOCKLE_IMAGE); both need the docker socket.
# Env: RO_WAIT_SECONDS (default 90) is how long the read-only run waits for PostgreSQL.
set -euo pipefail
# shellcheck disable=SC2016

SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.57.1}"
DOCKLE_IMAGE="${DOCKLE_IMAGE:-goodwithtech/dockle:v0.4.15}"
RO_WAIT_SECONDS="${RO_WAIT_SECONDS:-90}"
ORIGIN_TSV_PATH=/usr/share/percona/package-origins.tsv
DOCKER_SOCK=/var/run/docker.sock

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo ">> $*" >&2; }

[ "$#" -eq 3 ] || die "usage: $0 <baseline-image> <dhi-image> <outdir>"
BASELINE="$1"; DHI="$2"; OUT="$3"
for tool in docker trivy grype jq; do command -v "$tool" >/dev/null || die "$tool is required"; done
[ -S "$DOCKER_SOCK" ] || die "docker socket $DOCKER_SOCK not found"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
for img in "$BASELINE" "$DHI"; do
    docker image inspect "$img" >/dev/null 2>&1 || die "image $img not found locally (docker pull it first)"
done

# --- scanners ---------------------------------------------------------------------------------

# Run a tool container with the docker socket, writing into $OUT as the current user.
tool_container() {
    docker run --rm --user "$(id -u):$(id -g)" --group-add "$(stat -c %g "$DOCKER_SOCK")" \
        --tmpfs /tmp:mode=1777 -e HOME=/tmp -e XDG_CACHE_HOME=/tmp/.cache \
        -v "$DOCKER_SOCK:$DOCKER_SOCK" -v "$OUT:/out" "$@"
}

run_scanners() {
    local label="$1" img="$2"
    log "trivy: $img"
    trivy image --quiet --scanners vuln --format json --output "$OUT/trivy-$label.json" "$img" \
        || die "trivy failed for $img"
    log "grype: $img"
    grype "docker:$img" --quiet -o json >"$OUT/grype-$label.json" || die "grype failed for $img"
    log "syft: $img"
    tool_container "$SYFT_IMAGE" "docker:$img" --quiet \
        -o "spdx-json=/out/sbom-$label.spdx.json" -o "cyclonedx-json=/out/sbom-$label.cdx.json" \
        || die "syft failed for $img"
    log "dockle: $img"
    tool_container "$DOCKLE_IMAGE" -f json -o "/out/dockle-$label.json" "$img" \
        || die "dockle failed for $img"
    for f in trivy grype dockle; do
        jq -e . "$OUT/$f-$label.json" >/dev/null || die "$f-$label.json is not valid JSON"
    done
}

# --- metrics ----------------------------------------------------------------------------------

# "total N (C a, H b, M c, L d)" from a stream of severity strings on stdin.
sev_cell() {
    jq -rs '
      def n($s): [.[] | select(ascii_upcase == $s)] | length;
      "\(length) (C \(n("CRITICAL")), H \(n("HIGH")), M \(n("MEDIUM")), L \(n("LOW")))"'
}

trivy_cell() { # label, fixable(0|1)
    jq --argjson fixable "$2" '
      [.Results[]?.Vulnerabilities[]?
        | select($fixable == 0 or ((.FixedVersion // "") != ""))
        | {k: [.VulnerabilityID, .PkgName, .InstalledVersion], s: .Severity}]
      | unique_by(.k)[].s' "$OUT/trivy-$1.json" | sev_cell
}

grype_cell() {
    jq --argjson fixable "$2" '
      [.matches[]
        | select($fixable == 0 or (.vulnerability.fix.state == "fixed"))
        | {k: [.vulnerability.id, .artifact.name, .artifact.version], s: .vulnerability.severity}]
      | unique_by(.k)[].s' "$OUT/grype-$1.json" | sev_cell
}

package_count() {
    jq -r '[.components[]? | select((.purl // "") | test("^pkg:(deb|rpm)/"))] | length' "$OUT/sbom-$1.cdx.json"
}

size_cell() {
    local img="$1" raw gz
    raw="$(docker image inspect -f '{{.Size}}' "$img")"
    gz="$(docker save "$img" | gzip -c | wc -c)"
    echo "$((gz / 1024 / 1024)) MiB gzip'd save / $((raw / 1024 / 1024)) MiB uncompressed"
}

# Run a bash snippet in the image (bash builtins only; the DHI runtime has no find/grep/awk).
in_image() { docker run --rm --entrypoint bash "$1" -c "$2" _ "${@:3}"; }

presence_cell() { # image, command names...
    local img="$1"; shift
    local found
    found="$(in_image "$img" 'for c in "$@"; do p="$(command -v "$c" || true)"; [ -n "$p" ] && echo "$c"; done; true' "$@" \
        | paste -sd, -)"
    if [ -n "$found" ]; then echo "yes ($found)"; else echo "no"; fi
}

setuid_cell() {
    local n
    n="$(in_image "$1" 'shopt -s globstar nullglob dotglob; c=0
        for f in /usr/** /etc/** /opt/** /var/**; do
            [ -f "$f" ] && [ ! -L "$f" ] && { [ -u "$f" ] || [ -g "$f" ]; } && c=$((c + 1))
        done; echo $c')"
    echo "$n"
}

root_cell() {
    local img="$1" user uid
    user="$(docker image inspect -f '{{.Config.User}}' "$img")"
    uid="$(docker run --rm --entrypoint id "$img" -u)"
    if [ "$uid" = 0 ]; then echo "yes (image USER '${user:-root}', uid 0)"; else echo "no (image USER '${user:-root}', uid $uid)"; fi
}

sbom_cell() {
    local img="$1" sbom prov
    sbom="$(docker buildx imagetools inspect --format '{{json .SBOM}}' "$img" 2>/dev/null)" || sbom=""
    prov="$(docker buildx imagetools inspect --format '{{json .Provenance}}' "$img" 2>/dev/null)" || prov=""
    if [ -z "$sbom$prov" ]; then echo "not queryable (image not in a registry)"; return; fi
    local s="no" p="no"
    [ -n "$sbom" ] && [ "$sbom" != "{}" ] && [ "$sbom" != "null" ] && s="yes"
    [ -n "$prov" ] && [ "$prov" != "{}" ] && [ "$prov" != "null" ] && p="yes"
    echo "SBOM: $s, provenance: $p"
}

dockle_cell() {
    jq -r '.summary | "fatal \(.fatal), warn \(.warn), info \(.info), skip \(.skip), pass \(.pass)"' "$OUT/dockle-$1.json"
}

# Starts the image read-only with dropped capabilities and reports whether PostgreSQL comes up.
readonly_cell() {
    local img="$1" env_pgdata uid vol="" v cid name result="" i
    env_pgdata="$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$img" | sed -n 's/^PGDATA=//p')"
    uid="$(docker image inspect -f '{{.Config.User}}' "$img")"; uid="${uid:-0}"
    while read -r v; do
        [ -n "$v" ] && { [ "$env_pgdata" = "$v" ] || [[ "$env_pgdata" == "$v"/* ]]; } && vol="$v"
    done < <(docker image inspect -f '{{range $k, $_ := .Config.Volumes}}{{println $k}}{{end}}' "$img")
    [ -n "$vol" ] || vol="$env_pgdata"
    name="cmp-ro-$$-$RANDOM"
    docker volume create "$name" >/dev/null
    cid="$(docker run -d --name "$name" --read-only --cap-drop=ALL --security-opt no-new-privileges \
        --tmpfs "/run/postgresql:uid=$uid,gid=$uid" --tmpfs /tmp -v "$name:$vol" \
        -e POSTGRES_PASSWORD=x "$img")" || { docker volume rm "$name" >/dev/null; die "cannot start $img read-only"; }
    for ((i = 0; i < RO_WAIT_SECONDS; i += 2)); do
        if [ "$(docker inspect -f '{{.State.Running}}' "$cid")" != true ]; then break; fi
        if docker exec "$cid" pg_isready -q -h localhost 2>/dev/null; then result="works"; break; fi
        sleep 2
    done
    if [ -z "$result" ]; then
        result="fails: $(docker logs --tail 3 "$cid" 2>&1 | tr '\n' ' ' | cut -c1-200) [state: $(docker inspect -f '{{.State.Status}}' "$cid")]"
    fi
    docker rm -f "$cid" >/dev/null; docker volume rm "$name" >/dev/null
    echo "$result (data volume $vol)"
}

# --- origin breakdown -------------------------------------------------------------------------

# Rows "| origin | C | H | M | L | other | total |" from grype matches, grouped by origin.
origin_rows() { # label, origins-tsv ("" for single bucket)
    local tsv="${2:-}"
    jq -r --rawfile tsv "${tsv:-/dev/null}" '
      def origin_of($m):
        if ($tsv | length) == 0 then "all" else ($m[.artifact.name] // "unattributed") end;
      ($tsv | split("\n") | map(split("\t")) | map(select(length >= 3 and .[0] != "package"))
        | map({key: .[0], value: .[2]}) | from_entries) as $m
      | [.matches[] | {k: [.vulnerability.id, .artifact.name, .artifact.version],
                       o: origin_of($m), s: (.vulnerability.severity | ascii_upcase)}]
      | unique_by(.k) | group_by(.o)
      | map({o: .[0].o,
             c: map(select(.s == "CRITICAL")) | length, h: map(select(.s == "HIGH")) | length,
             m: map(select(.s == "MEDIUM")) | length,   l: map(select(.s == "LOW")) | length,
             t: length})
      | (if ($tsv | length) == 0 then [] else ["dhi","percona","debian-allowlist","unattributed"] end) as $order
      | . as $rows
      | (if ($order | length) == 0 then $rows else
           ($order | map(. as $o | ($rows | map(select(.o == $o))[0]) // {o: $o, c: 0, h: 0, m: 0, l: 0, t: 0}))
         end)[]
      | "| \(.o) | \(.c) | \(.h) | \(.m) | \(.l) | \(.t - .c - .h - .m - .l) | \(.t) |"' "$OUT/grype-$1.json"
}

origin_table() {
    echo "| Origin | Critical | High | Medium | Low | Other | Total |"
    echo "|---|---|---|---|---|---|---|"
    origin_rows "$@"
}

dockle_findings() {
    jq -r '.details[]? | select(.level != "PASS" and .level != "SKIP")
           | "| \(.code) | \(.level) | \(.title) |"' "$OUT/dockle-$1.json"
}

fetch_origins() {
    docker run --rm --entrypoint cat "$DHI" "$ORIGIN_TSV_PATH" >"$OUT/origins-dhi.tsv" \
        || die "cannot read $ORIGIN_TSV_PATH from $DHI"
    [ -s "$OUT/origins-dhi.tsv" ] || die "$ORIGIN_TSV_PATH in $DHI is empty"
}

# --- summary ----------------------------------------------------------------------------------

metric_row() { # name, fn, args...  -> "| name | baseline | dhi |"
    local name="$1" fn="$2"; shift 2
    log "measuring: $name"
    printf '| %s | %s | %s |\n' "$name" "$("$fn" "$BASELINE" "$@")" "$("$fn" "$DHI" "$@")"
}

label_row() { # name, fn, extra args: functions that take a label
    local name="$1" fn="$2"; shift 2
    log "measuring: $name"
    printf '| %s | %s | %s |\n' "$name" "$("$fn" baseline "$@")" "$("$fn" dhi "$@")"
}

write_summary() {
    {
        echo "# Image comparison"
        echo
        echo "- Baseline: \`$BASELINE\`"
        echo "- DHI: \`$DHI\`"
        echo
        echo "| Metric | Baseline | DHI |"
        echo "|---|---|---|"
        metric_row "Size" size_cell
        label_row "Packages" package_count
        label_row "CVEs (trivy)" trivy_cell 0
        label_row "CVEs (trivy, fixable)" trivy_cell 1
        label_row "CVEs (grype)" grype_cell 0
        label_row "CVEs (grype, fixable)" grype_cell 1
        metric_row "Package manager" presence_cell apt apt-get dpkg dnf microdnf yum rpm apk
        metric_row "Shells" presence_cell sh bash dash ash zsh ksh csh fish busybox
        metric_row "setuid" setuid_cell
        metric_row "Root by default" root_cell
        metric_row "SBOM / provenance attached" sbom_cell
        metric_row "Read-only run" readonly_cell
        label_row "Dockle" dockle_cell
        echo
        echo "Packages = dpkg/rpm entries in the syft inventory. CVEs are unique (id, package, version) matches;"
        echo "fixable = a fixed version is known. Size = \`docker save | gzip\` and \`docker image inspect\`."
        echo "Read-only run = \`--read-only --cap-drop=ALL --security-opt no-new-privileges\` with tmpfs for"
        echo "/run/postgresql and /tmp and a volume on the data path; ready = \`pg_isready\` within ${RO_WAIT_SECONDS}s."
        echo
        echo "## CVEs by origin (grype)"
        echo
        echo "Baseline (no origin report, single bucket):"
        echo
        origin_table baseline
        echo
        echo "DHI (joined with \`$ORIGIN_TSV_PATH\`; \`unattributed\` = not in the report, e.g. non-OS packages):"
        echo
        origin_table dhi "$OUT/origins-dhi.tsv"
        echo
        echo "## Dockle (CIS-DI) findings, excluding PASS/SKIP"
        for label in baseline dhi; do
            echo
            echo "### $label"
            echo
            echo "| Code | Level | Title |"
            echo "|---|---|---|"
            dockle_findings "$label"
        done
        echo
        echo "## Tools"
        echo
        echo "- trivy $(trivy --version | sed -n 's/^Version: //p'), grype $(grype version | sed -n 's/^Version: *//p')"
        echo "- syft: \`$SYFT_IMAGE\`, dockle: \`$DOCKLE_IMAGE\`"
    } >"$OUT/summary.md.tmp"
    mv "$OUT/summary.md.tmp" "$OUT/summary.md"
}

run_scanners baseline "$BASELINE"
run_scanners dhi "$DHI"
fetch_origins
write_summary
log "done: $OUT/summary.md"
