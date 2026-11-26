#!/usr/bin/env bash
# urkey local development and testing (Linux and macOS).
#
#   scripts/dev.sh setup            install deps, build WASM, create .dev.vars, migrate local D1
#   scripts/dev.sh dev [--fresh]    API (cf dev :8787) + web app (vite :5173); Ctrl-C stops both
#   scripts/dev.sh preview          production build of the app (CSP, service worker) on :4173, with the API
#   scripts/dev.sh test             fast checks: Rust fmt/clippy/tests/vectors + web/worker lint/typecheck/tests
#   scripts/dev.sh e2e              end to end: CLI + agent + sshd, then Playwright (dev + production)
#   scripts/dev.sh check            everything CI runs: test + deny + audit + builds + reproducibility + e2e
#   scripts/dev.sh cli -- <args>    run `urk` against the local API with a throwaway profile
#   scripts/dev.sh stop             stop servers left on :8787 / :5173 / :4173
#   scripts/dev.sh doctor           show which tools are present
#
# Local only: never deploys and never touches remote Cloudflare resources. Everything stays in
# local state (cloud/workers/api/.cloudflare/state). Use test data only (no real credentials).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
API_DIR="$ROOT/cloud/workers/api"
WEB_DIR="$ROOT/apps/web"
API_PORT=8787
WEB_PORT=5173
PREVIEW_PORT=4173
export CF_SEND_TELEMETRY=false
# Local servers must never go through an HTTP proxy.
export NO_PROXY="localhost,127.0.0.1${NO_PROXY:+,$NO_PROXY}"
export no_proxy="$NO_PROXY"

# ---------------------------------------------------------------- helpers

if [[ -t 1 ]]; then B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'; else B=; G=; R=; Y=; N=; fi
step() { printf '\n%s== %s%s\n' "$B" "$*" "$N"; }
ok() { printf '%s✔ %s%s\n' "$G" "$*" "$N"; }
warn() { printf '%s! %s%s\n' "$Y" "$*" "$N" >&2; }
die() { printf '%s✘ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
optional() { if [[ -n "${CI:-}" ]]; then die "$1"; else warn "$1; skipped"; fi; }

listening() { curl -s --noproxy '*' -o /dev/null -m 2 "http://localhost:$1/" 2>/dev/null; }

wait_for() { # url seconds name
  local i
  for ((i = 0; i < $2; i++)); do
    curl -sf --noproxy '*' -o /dev/null -m 2 "$1" 2>/dev/null && return 0
    sleep 1
  done
  die "$3 did not start within $2 s (log: $LOGS/$3.log)"
}

free_port() { # port
  local pids=""
  if have lsof; then pids=$(lsof -ti "tcp:$1" -sTCP:LISTEN 2>/dev/null || true)
  elif have fuser; then pids=$(fuser "$1/tcp" 2>/dev/null || true)
  fi
  if [[ -n "$pids" ]]; then
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    sleep 1
  fi
  if listening "$1"; then die "port $1 is still in use; stop that process first"; fi
}

# Background servers each get their own process group (job control), so stopping one also
# stops its children (workerd, esbuild).
set -m
PGIDS=()
LOGS="${TMPDIR:-/tmp}/urkey-dev"
mkdir -p "$LOGS"
start() { # name dir command...
  local name=$1 dir=$2
  shift 2
  (cd "$dir" && exec "$@") >"$LOGS/$name.log" 2>&1 &
  PGIDS+=("$!")
}
stop_all() {
  local g
  for g in "${PGIDS[@]:-}"; do [[ -n "$g" ]] && kill -- "-$g" 2>/dev/null || true; done
  PGIDS=()
}
trap stop_all EXIT
trap 'exit 130' INT TERM

# Node must satisfy package.json "engines" (.npmrc has engine-strict=true; jsdom needs this range).
NODE_RANGE="22.22.2+ (Node 22), 24.15.0+ (Node 24) or 26+"
need_node() {
  have node || die "Node.js is missing. Install Node 22 LTS (see .nvmrc), e.g. 'nvm install' or 'brew install node@22'."
  local v major minor patch
  v=$(node --version | sed 's/^v//')
  IFS=. read -r major minor patch <<<"$v"
  local okv=0
  if ((major == 22)) && ((minor > 22 || (minor == 22 && patch >= 2))); then okv=1
  elif ((major == 24)) && ((minor >= 15)); then okv=1
  elif ((major >= 26)); then okv=1
  fi
  ((okv)) || die "Node $v is too old for this repo; need $NODE_RANGE.
  Fix one of:
    nvm install && nvm use          # uses .nvmrc (Node 22)
    fnm install && fnm use          # same, with fnm
    brew upgrade node               # Homebrew (macOS): latest Node
  then rerun: scripts/dev.sh setup"
  have pnpm || die "pnpm is missing: corepack enable && corepack prepare pnpm@10.28.0 --activate"
}

need_wasm() {
  [[ -f "$WEB_DIR/src/wasm/wasm_bindings.js" ]] || { step "build WASM (first run)"; (cd "$ROOT" && pnpm wasm); }
}
need_node_modules() {
  need_node
  [[ -d "$ROOT/node_modules" ]] || { step "pnpm install (first run)"; (cd "$ROOT" && pnpm install --frozen-lockfile); }
}

start_api() { # [--fresh]
  free_port "$API_PORT"
  if [[ "${1:-}" == "--fresh" ]]; then rm -rf "$API_DIR/.cloudflare/state"; ok "local D1 wiped"; fi
  (cd "$API_DIR" && pnpm -s setup:dev >/dev/null) # .dev.vars (random local secret) + migrations
  start api "$API_DIR" pnpm -s exec cf dev --port "$API_PORT"
  wait_for "http://localhost:$API_PORT/v1/health" 90 api
  ok "API      http://localhost:$API_PORT  (health: /v1/health)"
}

# ---------------------------------------------------------------- commands

cmd_doctor() {
  step "tools"
  local t
  for t in cargo rustup node pnpm wasm-pack wasm-bindgen curl ssh sshd ssh-keygen python3 cargo-deny; do
    if have "$t"; then ok "$t: $("$t" --version 2>/dev/null | head -1 || echo present)"
    elif [[ "$t" == sshd && -x /usr/sbin/sshd ]]; then ok "sshd: /usr/sbin/sshd"
    else warn "$t: missing"; fi
  done
  have rustup && { rustup target list --installed | grep -q wasm32-unknown-unknown && ok "rust target wasm32-unknown-unknown" || warn "rustup target add wasm32-unknown-unknown"; }
  have wasm-bindgen && { wasm-bindgen --version | grep -q 0.2.130 || warn "wasm-bindgen-cli must be 0.2.130 (matches the crate pin)"; }
  echo
  echo "Needed: cargo, node 22+, pnpm, wasm-pack 0.15.1, wasm-bindgen 0.2.130 (setup/dev/test)."
  echo "Also for e2e: ssh, sshd, ssh-keygen. For check: cargo-deny, python3."
}

cmd_setup() {
  step "check tools"
  local t
  need_node
  for t in cargo wasm-pack wasm-bindgen; do have "$t" || die "$t is missing (run: scripts/dev.sh doctor)"; done
  rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown || rustup target add wasm32-unknown-unknown
  step "pnpm install"
  (cd "$ROOT" && pnpm install --frozen-lockfile)
  step "build WASM core for the web app"
  (cd "$ROOT" && pnpm wasm)
  step "local API secret + D1 migrations"
  (cd "$API_DIR" && pnpm -s setup:dev)
  step "build the CLI"
  (cd "$ROOT" && cargo build -q -p urkey-cli)
  ok "setup done. Next: scripts/dev.sh dev"
}

cmd_dev() {
  need_node_modules
  need_wasm
  step "start API and web app"
  start_api "${1:-}"
  free_port "$WEB_PORT"
  start web "$WEB_DIR" pnpm -s exec vite --port "$WEB_PORT" --strictPort
  wait_for "http://localhost:$WEB_PORT/" 60 web
  ok "Web app  http://localhost:$WEB_PORT"
  echo
  echo "Logs: $LOGS/{api,web}.log    CLI: scripts/dev.sh cli -- --help    Stop: Ctrl-C"
  echo "Account creation is rate-limited (10/hour per IP); use 'dev --fresh' to reset local data."
  wait
}

cmd_preview() {
  need_node_modules
  need_wasm
  step "production build (CSP + Trusted Types + service worker)"
  (cd "$WEB_DIR" && pnpm exec vite build >"$LOGS/build.log" 2>&1) || die "build failed (log: $LOGS/build.log)"
  ok "release hash: $(sed -n 's/.*"hash": *"\([0-9a-f]*\)".*/\1/p' "$WEB_DIR/.cloudflare/output/v1/workers/default/assets/release.json")"
  start_api "${1:-}"
  free_port "$PREVIEW_PORT"
  start preview "$WEB_DIR" pnpm -s exec vite preview --port "$PREVIEW_PORT" --strictPort
  wait_for "http://localhost:$PREVIEW_PORT/" 90 preview
  ok "Preview  http://localhost:$PREVIEW_PORT  (production headers; service worker pins this build)"
  echo "Stop: Ctrl-C"
  wait
}

cmd_test() {
  need_node_modules
  need_wasm
  step "Rust: fmt, clippy, tests, crypto vectors"
  (cd "$ROOT" && cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings \
    && cargo test --workspace -q && cargo test -p crypto-core --features test-vectors -q) || die "Rust checks failed"
  step "Web + Worker: lint, typecheck, unit tests"
  (cd "$ROOT" && pnpm -r lint && pnpm -r typecheck && pnpm -r test) || die "web/worker checks failed"
  ok "fast checks passed"
}

cmd_e2e() {
  need_node_modules
  need_wasm
  have ssh && have ssh-keygen && { have sshd || [[ -x /usr/sbin/sshd ]]; } \
    || die "e2e needs OpenSSH client and server (macOS: built in; Debian/Ubuntu: apt install openssh-client openssh-server)"
  free_port "$API_PORT"; free_port "$WEB_PORT"; free_port "$PREVIEW_PORT"
  step "CLI + SSH agent + sshd + export/restore (tests/integration/cli_e2e.sh)"
  "$ROOT/tests/integration/cli_e2e.sh" || die "CLI end-to-end failed"
  free_port "$API_PORT"
  step "browser: Playwright (dev server + production build); starts its own servers"
  # CI=1: Playwright starts fresh servers (empty local D1) and stops them afterwards.
  (cd "$WEB_DIR" && CI=1 pnpm exec playwright test --trace off --reporter=line) \
    || die "browser end-to-end failed (results: $WEB_DIR/test-results)"
  ok "end-to-end passed"
}

cmd_check() {
  cmd_test
  # In CI (CI set) a missing tool is a failure; locally it is skipped with a warning.
  step "dependencies: cargo deny + pnpm audit"
  if have cargo-deny; then (cd "$ROOT" && cargo deny check) || die "cargo deny failed"
  else optional "cargo-deny missing (cargo install cargo-deny)"; fi
  (cd "$ROOT" && pnpm audit --prod) || die "pnpm audit failed"
  step "independent vector check (Python)"
  if have python3 && python3 -c "import argon2, cryptography" 2>/dev/null; then
    python3 "$ROOT/tests/interop/python/verify_crypto_v1.py" || die "Python vector check failed"
  else optional "python3 with 'cryptography' missing (pip install -r tests/interop/python/requirements.txt)"; fi
  step "crypto vectors inside WASM (Node)"
  (cd "$ROOT" && wasm-pack test --node crates/crypto-core --features test-vectors --test wasm) \
    || die "WASM vector test failed"
  step "builds + reproducible release hash"
  local rel="$WEB_DIR/.cloudflare/output/v1/workers/default/assets/release.json" first second
  (cd "$ROOT" && pnpm --filter web build >"$LOGS/build.log" 2>&1) || die "web build failed (log: $LOGS/build.log)"
  first=$(cat "$rel")
  rm -rf "$WEB_DIR/.cloudflare/output"
  (cd "$ROOT" && pnpm --filter web build >"$LOGS/build.log" 2>&1) || die "web build failed"
  second=$(cat "$rel")
  [[ "$first" == "$second" ]] || die "release hash differs between two builds"
  ok "reproducible: $(sed -n 's/.*"hash": *"\([0-9a-f]*\)".*/\1/p' "$rel")"
  (cd "$ROOT" && pnpm --filter api build >/dev/null) || die "API build failed"
  (cd "$API_DIR" && pnpm -s exec cf deploy --dry-run >/dev/null) || die "API deploy dry run failed"
  (cd "$WEB_DIR" && pnpm -s exec cf deploy --dry-run >/dev/null) || die "app deploy dry run failed"
  ok "deploy dry runs passed (nothing deployed)"
  cmd_e2e
  ok "all checks passed"
}

cmd_cli() {
  # A throwaway profile per shell session unless URKEY_HOME is set. On macOS urk uses the
  # Keychain (entries are scoped to this directory).
  export URKEY_HOME="${URKEY_HOME:-$LOGS/cli-profile}"
  (cd "$ROOT" && cargo build -q -p urkey-cli)
  [[ "${1:-}" == "init" || -f "$URKEY_HOME/vault.db" ]] \
    || warn "new profile in $URKEY_HOME; start with: scripts/dev.sh cli init --server http://localhost:$API_PORT"
  exec "$ROOT/target/debug/urk" "$@"
}

cmd_stop() {
  local p
  for p in "$API_PORT" "$WEB_PORT" "$PREVIEW_PORT"; do
    if listening "$p"; then free_port "$p"; ok "stopped :$p"; fi
  done
  ok "nothing left listening on :$API_PORT :$WEB_PORT :$PREVIEW_PORT"
}

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; }

cmd=${1:-help}
shift || true
[[ "${1:-}" == "--" ]] && shift
case "$cmd" in
  setup) cmd_setup ;;
  dev) cmd_dev "$@" ;;
  preview) cmd_preview "$@" ;;
  test) cmd_test ;;
  e2e) cmd_e2e ;;
  check) cmd_check ;;
  cli) trap - EXIT; cmd_cli "$@" ;;
  stop) cmd_stop ;;
  doctor) cmd_doctor ;;
  help | -h | --help) usage ;;
  *) usage; die "unknown command: $cmd" ;;
esac
