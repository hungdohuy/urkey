#!/usr/bin/env bash
# Self-hosted server restored from an older backup (owner item O-14, sync.md §7.1), end to end
# on the Docker Compose stack, with the `urk` CLI as the devices.
#
#   tests/integration/selfhost_restore.sh      (from the repo root; needs Docker + cargo)
#
# Uses its own Compose project (urkey-restore-test) and its own volumes, ports 8080/8787 and
# throwaway CLI profiles. It never touches another project's data. Set URKEY_COMPOSE_FILES to
# extra `-f file` arguments if the build needs them (e.g. a proxy override).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
PROJECT=urkey-restore-test
URK="$ROOT/target/debug/urk"
PASSWORD="test-only restore e2e password"
EMAIL="restore-$(date +%s)@example.test"
SERVER=http://localhost:8787
# shellcheck disable=SC2206
COMPOSE=(docker compose -p "$PROJECT" -f "$ROOT/compose.yaml" ${URKEY_COMPOSE_FILES:-})
cleanup() {
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
wait_api() {
  for _ in $(seq 1 60); do
    [[ "$(docker inspect -f '{{.State.Health.Status}}' "$PROJECT-api-1" 2>/dev/null)" == healthy ]] && return 0
    sleep 2
  done
  fail "the API did not become healthy"
}
VOLUME="${PROJECT}_urkey-data"
backup() { docker run --rm -v "$VOLUME":/data -v "$WORK":/backup busybox:1.37.0 sh -c 'umask 077 && tar czf /backup/data.tgz -C /data .'; }
restore() { docker run --rm -v "$VOLUME":/data -v "$WORK":/backup busybox:1.37.0 sh -c 'rm -rf /data/* && tar xzf /backup/data.tgz -C /data'; }
u() { local n=$1; shift; URKEY_HOME="$WORK/$n" "$URK" "$@"; }
pw() { printf '%s\n' "$PASSWORD"; }
titles() { pw | u "$1" item list --password-stdin 2>/dev/null | sed -E 's/^[^ ]+ +[^ ]+ +//; s/ {2,}.*$//' | sort | tr '\n' '|'; }

step "build the CLI and start the Compose stack"
(cd "$ROOT" && cargo build -q -p urkey-cli)
"${COMPOSE[@]}" up -d --build >/dev/null
wait_api

step "device 1: account and an item"
u d1 init --server "$SERVER" --name "restore e2e 1" >/dev/null
KIT=$(pw | u d1 account create --email "$EMAIL" --password-stdin)
SECRET=$(printf '%s\n' "$KIT" | sed -n 's/^Secret Key: *//p')
[[ "$SECRET" == UK1-* ]] || fail "no Secret Key"
pw | u d1 item add-login --title "Before backup" --username u --password-stdin >/dev/null

step "operator backs up the server"
"${COMPOSE[@]}" stop api >/dev/null
backup
"${COMPOSE[@]}" start api >/dev/null
wait_api

step "work continues after the backup: device 1 adds an item, device 2 joins and edits"
pw | u d1 item add-login --title "After backup" --username u --password-stdin >/dev/null
u d2 init --server "$SERVER" --name "restore e2e 2" >/dev/null
printf '%s\n%s\n' "$PASSWORD" "$SECRET" | u d2 login --email "$EMAIL" --password-stdin >/dev/null
[[ "$(titles d2)" == "After backup|Before backup|" ]] || fail "device 2 does not see both items: $(titles d2)"

step "operator restores the OLD backup"
"${COMPOSE[@]}" stop api >/dev/null
restore
"${COMPOSE[@]}" start api >/dev/null
wait_api

step "device 1 notices the rollback and pauses"
if pw | u d1 sync --password-stdin >"$WORK/sync.out" 2>"$WORK/sync.err"; then fail "sync succeeded against a rolled-back server"; fi
grep -q "older data" "$WORK/sync.err" || fail "no rollback message: $(cat "$WORK/sync.err")"
grep -q -- "--resync" "$WORK/sync.err" || fail "the message does not tell how to recover"

step "device 1 resyncs: nothing it had is lost"
OUT=$(pw | u d1 sync --resync --password-stdin 2>&1) || fail "resync failed: $OUT"
[[ "$(titles d1)" == "After backup|Before backup|" ]] || fail "device 1 lost items: $(titles d1)"

step "device 2 joined after the backup: the restored server does not know it"
if OUT=$(pw | u d2 sync --password-stdin 2>&1); then fail "an unknown device could sync"; fi
grep -q "refused the sign-in" <<<"$OUT" || fail "unexpected message for an unknown device: $OUT"
# Signing in again registers the device; its local data is kept.
printf '%s\n%s\n' "$PASSWORD" "$SECRET" | u d2 login --email "$EMAIL" --password-stdin >/dev/null || fail "device 2 could not sign in again"

step "device 2 resyncs too: still exactly one copy of each item"
OUT=$(pw | u d2 sync --resync --password-stdin 2>&1) || fail "device 2 resync failed: $OUT"
[[ "$(titles d2)" == "After backup|Before backup|" ]] || fail "device 2 has duplicates or lost items: $(titles d2)"

step "a brand-new device sees the repaired server"
u d3 init --server "$SERVER" --name "restore e2e 3" >/dev/null
printf '%s\n%s\n' "$PASSWORD" "$SECRET" | u d3 login --email "$EMAIL" --password-stdin >/dev/null
[[ "$(titles d3)" == "After backup|Before backup|" ]] || fail "device 3 does not see both items once: $(titles d3)"

printf '\nSELF-HOST RESTORE CHECKS PASSED\n'
