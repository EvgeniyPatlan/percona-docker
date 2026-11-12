#!/usr/bin/env bash
# Entrypoint behaviour checks for the PG18 DHI image.
# Usage: tests/test-entrypoint.sh <image>
set -euo pipefail

IMAGE="${1:?usage: $0 <image>}"
FAILURES=0
PREFIX="pgep-$$-$RANDOM"
CONTAINERS=()
VOLUMES=()
TMPDIRS=()

fail() { echo "FAIL: $*"; FAILURES=$((FAILURES + 1)); }
pass() { echo "PASS: $*"; }

cleanup() {
    local c v d
    for c in "${CONTAINERS[@]:-}"; do [ -n "$c" ] && docker rm -fv "$c" >/dev/null 2>&1 || true; done
    for v in "${VOLUMES[@]:-}"; do [ -n "$v" ] && docker volume rm -f "$v" >/dev/null 2>&1 || true; done
    for d in "${TMPDIRS[@]:-}"; do [ -n "$d" ] && rm -rf "$d" || true; done
}
trap cleanup EXIT

# start NAME [docker run args...]  (image and its command are appended)
start() {
    local name="$PREFIX-$1"; shift
    CONTAINERS+=("$name")
    docker run -d --name "$name" "$@" "$IMAGE" >/dev/null
}
cname() { echo "$PREFIX-$1"; }

# wait_ready NAME: wait until the final (TCP-listening) server accepts connections
wait_ready() {
    local name="$PREFIX-$1" i
    for i in $(seq 1 90); do
        if docker exec "$name" pg_isready -q -h 127.0.0.1 -U postgres 2>/dev/null; then return 0; fi
        [ "$(docker inspect -f '{{.State.Running}}' "$name")" = "true" ] || return 1
        sleep 1
    done
    return 1
}

# container_ip NAME: address on the bridge network (loopback is "trust" in the default pg_hba.conf)
container_ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PREFIX-$1"; }

# sql NAME PASSWORD USER DB QUERY  (over TCP on the container IP, so password auth is exercised)
sql() {
    docker exec -e PGPASSWORD="$2" "$PREFIX-$1" psql -h "$(container_ip "$1")" -U "$3" -d "$4" -v ON_ERROR_STOP=1 -Atq -c "$5"
}

mktmp() { local d; d="$(mktemp -d)"; chmod 755 "$d"; TMPDIRS+=("$d"); echo "$d"; }

test_password_default() {
    start basic -e POSTGRES_PASSWORD=secret
    if wait_ready basic && [ "$(sql basic secret postgres postgres 'select 1')" = "1" ]; then
        pass "POSTGRES_PASSWORD: psql select 1 works over TCP (password auth)"
    else
        fail "POSTGRES_PASSWORD: server did not come up"; docker logs "$(cname basic)" 2>&1 | tail -20
        return
    fi
    if docker exec -e PGPASSWORD=wrong "$(cname basic)" psql -h "$(container_ip basic)" -U postgres -Atqc 'select 1' >/dev/null 2>&1; then
        fail "wrong password was accepted"
    else
        pass "wrong password rejected"
    fi
    [ "$(docker exec "$(cname basic)" id -u)" = "70" ] && pass "server runs as uid 70" || fail "server not uid 70"
}

test_user_db() {
    start userdb -e POSTGRES_USER=appuser -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=appdb
    if wait_ready userdb && [ "$(sql userdb pw appuser appdb 'select current_user || current_database()')" = "appuserappdb" ]; then
        pass "POSTGRES_USER / POSTGRES_DB honoured"
    else
        fail "POSTGRES_USER / POSTGRES_DB not honoured"; docker logs "$(cname userdb)" 2>&1 | tail -20
    fi
}

test_password_file() {
    local d; d="$(mktmp)"
    printf 'filesecret' > "$d/pw"; chmod 644 "$d/pw"
    start pwfile -e POSTGRES_PASSWORD_FILE=/run/secrets/pw -v "$d/pw:/run/secrets/pw:ro"
    if wait_ready pwfile && [ "$(sql pwfile filesecret postgres postgres 'select 1')" = "1" ]; then
        pass "POSTGRES_PASSWORD_FILE works"
    else
        fail "POSTGRES_PASSWORD_FILE failed"; docker logs "$(cname pwfile)" 2>&1 | tail -20
    fi
}

test_initdb_scripts() {
    local d; d="$(mktmp)"
    echo "CREATE TABLE from_sql (v int); INSERT INTO from_sql VALUES (42);" > "$d/10-a.sql"
    printf '#!/usr/bin/env bash\npsql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -c "CREATE TABLE from_exec_sh (v int)"\n' > "$d/20-b.sh"
    chmod 755 "$d/20-b.sh"
    printf 'psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -c "CREATE TABLE from_sourced_sh (v int)"\n' > "$d/30-c.sh"
    chmod 644 "$d/30-c.sh"
    chmod 644 "$d/10-a.sql"
    start initdb -e POSTGRES_PASSWORD=pw -v "$d:/docker-entrypoint-initdb.d:ro"
    if wait_ready initdb \
        && [ "$(sql initdb pw postgres postgres 'select v from from_sql')" = "42" ] \
        && [ "$(sql initdb pw postgres postgres 'select count(*) from from_exec_sh')" = "0" ] \
        && [ "$(sql initdb pw postgres postgres 'select count(*) from from_sourced_sh')" = "0" ]; then
        pass "docker-entrypoint-initdb.d: .sql, executable .sh and sourced .sh ran"
    else
        fail "docker-entrypoint-initdb.d scripts did not run"; docker logs "$(cname initdb)" 2>&1 | tail -20
    fi
}

test_extensions_and_tde() {
    CONTAINERS+=("$(cname ext)")
    docker run -d --name "$(cname ext)" -e POSTGRES_PASSWORD=pw "$IMAGE" postgres \
        -c shared_preload_libraries=pg_tde,pg_stat_monitor,pgaudit,pg_cron >/dev/null
    if ! wait_ready ext; then
        fail "server with shared_preload_libraries did not start"; docker logs "$(cname ext)" 2>&1 | tail -20
        return
    fi
    local ext
    for ext in pg_tde pg_stat_monitor pgaudit set_user pg_repack vector pg_cron; do
        if sql ext pw postgres postgres "CREATE EXTENSION $ext" >/dev/null 2>&1; then
            pass "CREATE EXTENSION $ext"
        else
            fail "CREATE EXTENSION $ext"
        fi
    done
    local out
    if out="$(sql ext pw postgres postgres "
        SELECT pg_tde_add_database_key_provider_file('file-vault','/var/lib/postgresql/18/data/keyring.file');
        SELECT pg_tde_create_key_using_database_key_provider('k1','file-vault');
        SELECT pg_tde_set_key_using_database_key_provider('k1','file-vault');
        CREATE TABLE tde_t (x int) USING tde_heap;
        INSERT INTO tde_t VALUES (7);
        SELECT x FROM tde_t" 2>&1 | tail -1)" && [ "$out" = "7" ]; then
        pass "pg_tde file keyring: encrypted table created and read"
    else
        fail "pg_tde encrypted table: $out"
    fi
}

test_root_refused() {
    local out rc=0
    out="$(docker run --rm --user 0 -e POSTGRES_PASSWORD=pw "$IMAGE" 2>&1)" || rc=$?
    if [ "$rc" -ne 0 ] && [[ "$out" == *"must not run as root"* ]]; then
        pass "--user 0 refused (exit $rc, 'must not run as root')"
    else
        fail "--user 0 not refused (exit $rc): $out"
    fi
}

test_arbitrary_uid() {
    # Pinned behaviour: an arbitrary non-root UID (gid 0, OpenShift style) works through nss_wrapper
    # provided PGDATA and the socket directory are writable for it (tmpfs here).
    local uid=1000750000
    start arb --user "$uid:0" -e POSTGRES_PASSWORD=pw \
        --tmpfs "/var/lib/postgresql/18/data:uid=$uid,gid=0,mode=0700" \
        --tmpfs "/var/run/postgresql:uid=$uid,gid=0,mode=2775"
    if wait_ready arb && [ "$(sql arb pw postgres postgres 'select 1')" = "1" ]; then
        pass "arbitrary uid $uid:0 starts and serves queries"
    else
        fail "arbitrary uid $uid:0 did not start"; docker logs "$(cname arb)" 2>&1 | tail -20
    fi
}

test_hardened_runtime() {
    local vol="$PREFIX-data"
    VOLUMES+=("$vol")
    start ro --read-only --cap-drop=ALL --security-opt no-new-privileges \
        --tmpfs /var/run/postgresql:uid=70,gid=70 --tmpfs /tmp \
        -v "$vol:/var/lib/postgresql" -e POSTGRES_PASSWORD=pw
    if wait_ready ro && [ "$(sql ro pw postgres postgres 'select 1')" = "1" ]; then
        pass "read-only rootfs + cap-drop=ALL + no-new-privileges starts (tmpfs /var/run/postgresql)"
    else
        fail "hardened runtime did not start"; docker logs "$(cname ro)" 2>&1 | tail -20
    fi
}

test_password_default
test_user_db
test_password_file
test_initdb_scripts
test_extensions_and_tde
test_root_refused
test_arbitrary_uid
test_hardened_runtime

if [ "$FAILURES" -eq 0 ]; then echo "ALL PASSED"; else echo "$FAILURES FAILED"; exit 1; fi
