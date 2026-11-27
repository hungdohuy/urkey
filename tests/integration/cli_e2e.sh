#!/usr/bin/env bash
# End-to-end: Worker (cf dev, local D1) + two `urk` devices + SSH agent + real sshd.
# Usage: tests/integration/cli_e2e.sh   (from the repo root; needs OpenSSH client and server)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
PORT=${URKEY_E2E_PORT:-8787}
SSHD_PORT=${URKEY_E2E_SSHD_PORT:-22022}
URK="$ROOT/target/debug/urk"
PASSWORD="test-only e2e master password"
EMAIL="e2e-$(date +%s)@example.test"
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

step "build urk"
(cd "$ROOT" && cargo build -q -p urkey-cli)

step "start the API (cf dev, fresh local D1)"
API_DIR="$ROOT/cloud/workers/api"
rm -rf "$API_DIR/.cloudflare/state"
(cd "$API_DIR" && pnpm -s setup:dev >/dev/null)
(cd "$API_DIR" && exec pnpm -s exec cf dev --port "$PORT" >"$WORK/api.log" 2>&1) & pids+=($!)
for _ in $(seq 1 60); do curl -sf --noproxy '*' "http://localhost:$PORT/v1/health" >/dev/null && break; sleep 1; done
curl -sf --noproxy '*' "http://localhost:$PORT/v1/health" >/dev/null || { cat "$WORK/api.log"; fail "API did not start"; }

D1="$WORK/device1"; D2="$WORK/device2"
u1() { URKEY_HOME="$D1" "$URK" "$@"; }
u2() { URKEY_HOME="$D2" "$URK" "$@"; }

step "device 1: create account"
u1 init --server "http://localhost:$PORT" --name "E2E laptop" >/dev/null
KIT=$(printf '%s\n' "$PASSWORD" | u1 account create --email "$EMAIL" --password-stdin)
SECRET=$(printf '%s\n' "$KIT" | sed -n 's/^Secret Key: *//p')
[[ "$SECRET" == UK1-* ]] || fail "no Secret Key in the Emergency Kit"
printf '%s\n' "$KIT" | grep -q '^Recovery Key: *UKR1-' || fail "no Recovery Key in the Emergency Kit"

step "device 1: add a login"
printf '%s\n' "$PASSWORD" | u1 item add-login --title "Example login" --username alice --url https://example.com --password-stdin
WRONG=$(printf 'wrong password\n' | u1 item list --password-stdin 2>&1 || true)
grep -q "Couldn't unlock" <<<"$WRONG" || fail "wrong password was not refused"

step "device 2: sign in and see the login"
u2 init --server "http://localhost:$PORT" --name "E2E desktop" >/dev/null
printf '%s\n%s\n' "$PASSWORD" "$SECRET" | u2 login --email "$EMAIL" --password-stdin
printf '%s\n' "$PASSWORD" | u2 item list --password-stdin | grep -q "Example login" || fail "login not synced to device 2"
PW1=$(printf '%s\n' "$PASSWORD" | u1 item get "Example" --field password --password-stdin)
PW2=$(printf '%s\n' "$PASSWORD" | u2 item get "Example" --field password --password-stdin)
[[ -n "$PW1" && "$PW1" == "$PW2" ]] || fail "password differs between devices"

step "device 2: import an SSH key"
ssh-keygen -q -t ed25519 -N "" -C "test-only-e2e" -f "$WORK/id_e2e"
printf '%s\n' "$PASSWORD" | u2 ssh import "$WORK/id_e2e" --title "E2E key" --password-stdin
printf '%s\n' "$PASSWORD" | u1 ssh list --password-stdin | grep -q "E2E key" || fail "SSH key not synced to device 1"

step "local sshd that trusts only the imported key"
mkdir -p "$WORK/sshd"
ssh-keygen -q -t ed25519 -N "" -f "$WORK/sshd/host_key"
cp "$WORK/id_e2e.pub" "$WORK/sshd/authorized_keys"
chmod 600 "$WORK/sshd/authorized_keys"
cat >"$WORK/sshd/sshd_config" <<CFG
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $WORK/sshd/host_key
AuthorizedKeysFile $WORK/sshd/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
StrictModes no
UsePAM no
PidFile $WORK/sshd/sshd.pid
CFG
mkdir -p /run/sshd 2>/dev/null || true
/usr/sbin/sshd -D -f "$WORK/sshd/sshd_config" -E "$WORK/sshd/log" & pids+=($!)
sleep 1
rm -f "$WORK/id_e2e"   # the private key now exists only in the vault

step "device 1: copy a password; the clipboard clears itself (R-ITEM-7)"
CLIP="$WORK/clipboard"
printf '#!/bin/sh\ncat > "%s"\n' "$CLIP" >"$WORK/fake-copy"
printf '#!/bin/sh\ncat "%s" 2>/dev/null\n' "$CLIP" >"$WORK/fake-paste"
chmod +x "$WORK/fake-copy" "$WORK/fake-paste"
export URKEY_CLIPBOARD_COPY="$WORK/fake-copy" URKEY_CLIPBOARD_PASTE="$WORK/fake-paste" URKEY_CLIPBOARD_CLEAR_SECS=2
OUT=$(printf '%s\n' "$PASSWORD" | u1 item copy "Example" --password-stdin)
grep -q "Password copied. Clears in 2 s." <<<"$OUT" || fail "copy message"
grep -qF -e "$PW1" <<<"$OUT" && fail "copy printed the password"
[[ "$(cat "$CLIP")" == "$PW1" ]] || fail "clipboard does not hold the password"
sleep 4
[[ -z "$(cat "$CLIP")" ]] || fail "clipboard was not cleared"
printf '%s\n' "$PASSWORD" | u1 item copy "Example" --password-stdin >/dev/null
printf 'something the user copied later' >"$CLIP"
sleep 4
[[ "$(cat "$CLIP")" == "something the user copied later" ]] || fail "clearing wiped a newer clipboard value"
unset URKEY_CLIPBOARD_COPY URKEY_CLIPBOARD_PASTE URKEY_CLIPBOARD_CLEAR_SECS

step "device 1: agent + unlock, then ssh with the vault key"
SOCK="$D1/agent.sock"
URKEY_HOME="$D1" "$URK" agent run 2>"$WORK/agent.log" & pids+=($!)
for _ in $(seq 1 20); do [[ -S "$SOCK" ]] && break; sleep 0.2; done
printf '%s\n' "$PASSWORD" | u1 unlock --minutes 5 --password-stdin | grep -q "1 SSH key" || fail "key not loaded"
SSH_AUTH_SOCK="$SOCK" ssh-add -l | grep -q "test-only-e2e" || fail "ssh-add does not list the key"
SSH_OPTS=(-p "$SSHD_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentityAgent="$SOCK" -o IdentitiesOnly=no -o BatchMode=yes -o LogLevel=ERROR)
OUT=$(ssh "${SSH_OPTS[@]}" "$(whoami)@127.0.0.1" echo urkey-agent-ok)
[[ "$OUT" == "urkey-agent-ok" ]] || fail "ssh through the agent failed"

step "lock: ssh must fail"
u1 lock >/dev/null
if ssh "${SSH_OPTS[@]}" "$(whoami)@127.0.0.1" true 2>/dev/null; then fail "ssh still works after lock"; fi

step "device 1 revokes device 2"
ID2=$(u1 device list | grep "E2E desktop" | cut -c1-8)
printf '%s\n' "$PASSWORD" | u1 device revoke "$ID2" --password-stdin
# Device 2's next sync is refused.
if printf '%s\n' "$PASSWORD" | u2 sync --password-stdin 2>"$WORK/revoked.err"; then fail "revoked device could still sync"; fi
grep -q "removed from your account" "$WORK/revoked.err" || fail "revoked device did not get device_revoked"

step "encrypted export from device 1, restore into a fresh account (roadmap P7)"
printf '%s\n' "$PASSWORD" | u1 export --out "$WORK/vault.urkey-export" --password-stdin | grep -q "Exported 2 items" || fail "export"
[[ $(stat -c %a "$WORK/vault.urkey-export") == 600 ]] || fail "export file is not 0600"
if grep -qF -e "Example login" -e alice -e "$PW1" "$WORK/vault.urkey-export"; then fail "plaintext in the export"; fi
D3="$WORK/device3"; u3() { URKEY_HOME="$D3" "$URK" "$@"; }
PASSWORD3="test-only e2e second account password"
u3 init --server "http://localhost:$PORT" --name "E2E fresh" >/dev/null
printf '%s\n' "$PASSWORD3" | u3 account create --email "fresh-$EMAIL" --password-stdin >/dev/null
if printf '%s\n%s\n%s\n' "$PASSWORD3" "wrong password" "$SECRET" | u3 restore "$WORK/vault.urkey-export" --password-stdin 2>/dev/null; then fail "restore with a wrong password"; fi
printf '%s\n%s\n%s\n' "$PASSWORD3" "$PASSWORD" "$SECRET" | u3 restore "$WORK/vault.urkey-export" --password-stdin | grep -q "Restored 2 items" || fail "restore"
PW3=$(printf '%s\n' "$PASSWORD3" | u3 item get "Example" --field password --password-stdin)
[[ "$PW3" == "$PW1" ]] || fail "restored password differs"
printf '%s\n' "$PASSWORD3" | u3 ssh list --password-stdin | grep -q "E2E key" || fail "SSH key not restored"

printf '\nALL CLI END-TO-END CHECKS PASSED\n'
