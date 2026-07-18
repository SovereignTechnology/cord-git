#!/usr/bin/env bash
# CORD-git Phase 3 end-to-end test against a live GRASP-P server.
# Scenarios: create+push, owner clone, contributor(read-only) refusal,
# concurrent-push CAS refusal. Exit 0 = all green.
set -uo pipefail

SERVER_BIN="${SERVER_BIN:-$HOME/ngit-private-impl/ref/ngit-grasp/target/release/ngit-grasp}"
CORD_BIN="${CORD_BIN:-$HOME/ngit-private-impl/cord-git/target/release/cord-git}"
PORT="${PORT:-7361}"
RELAY="ws://127.0.0.1:${PORT}"
SERVER="http://127.0.0.1:${PORT}"

WORK="$(mktemp -d)"
SRV_DATA="$WORK/srvdata"
mkdir -p "$SRV_DATA"
FAILED=0
SRV_PID=""

cleanup() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
  wait "$SRV_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILED=1; }

echo "=== workdir: $WORK ==="

# --- spawn server -----------------------------------------------------------
NGIT_DOMAIN="127.0.0.1:${PORT}" \
NGIT_BIND_ADDRESS="127.0.0.1:${PORT}" \
NGIT_DATABASE_BACKEND=memory \
NGIT_PRIVATE_REPOS_ENABLE=true \
NGIT_RELAY_DATA_PATH="$SRV_DATA/relay" \
NGIT_GIT_DATA_PATH="$SRV_DATA/git" \
"$SERVER_BIN" >"$WORK/server.log" 2>&1 &
SRV_PID=$!

# wait for readiness (GET / -> 200)
for _ in $(seq 1 50); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$SERVER/" 2>/dev/null || true)"
  [ "$code" = "200" ] && break
  sleep 0.2
done
if [ "$(curl -s -o /dev/null -w '%{http_code}' "$SERVER/")" != "200" ]; then
  echo "server did not start; log:"; cat "$WORK/server.log"; exit 2
fi
echo "server up on $PORT (pid $SRV_PID)"

# --- scenario 2: create + push ---------------------------------------------
OWNER_HOME="$WORK/owner-cfg"
REPO="$WORK/owner-repo"
mkdir -p "$REPO"
git -C "$REPO" init --quiet
git -C "$REPO" config user.email e2e@example.com
git -C "$REPO" config user.name e2e
git -C "$REPO" checkout -q -b main
echo "hello cord-git" > "$REPO/README.md"
mkdir -p "$REPO/src"
echo "fn main() {}" > "$REPO/src/main.rs"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "first commit"
echo "line two" >> "$REPO/README.md"
git -C "$REPO" commit -aq -m "second commit"
ORIG_HEAD="$(git -C "$REPO" rev-parse HEAD)"

CREATE_OUT="$(CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" create demo --relay "$RELAY" --server "$SERVER" --dir "$REPO" 2>&1)"
echo "$CREATE_OUT"
CID="$(printf '%s\n' "$CREATE_OUT" | sed -n 's/.*community_id: //p' | tr -d ' ')"
if [ -z "$CID" ]; then fail "create (no community_id)"; echo "$CREATE_OUT"; exit 1; fi
pass "create -> $CID"

if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" push --dir "$REPO" >"$WORK/push1.log" 2>&1; then
  pass "push (genesis)"
else
  fail "push (genesis)"; cat "$WORK/push1.log"
fi

# --- scenario 3: owner clone round-trips -----------------------------------
CLONE="$WORK/owner-clone"
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" clone "$CID" "$CLONE" >"$WORK/clone1.log" 2>&1; then
  CLONE_HEAD="$(git -C "$CLONE" rev-parse HEAD 2>/dev/null || echo none)"
  if [ "$CLONE_HEAD" = "$ORIG_HEAD" ] && diff -q "$REPO/README.md" "$CLONE/README.md" >/dev/null 2>&1 \
     && diff -q "$REPO/src/main.rs" "$CLONE/src/main.rs" >/dev/null 2>&1; then
    pass "clone (owner) HEAD=$CLONE_HEAD, contents match"
  else
    fail "clone (owner) mismatch: head=$CLONE_HEAD orig=$ORIG_HEAD"
  fi
else
  fail "clone (owner)"; cat "$WORK/clone1.log"
fi

# --- scenario 4b: read-only contributor cannot push ------------------------
# Simulate a read-only member: a keystore with the write_secret stripped.
RO_HOME="$WORK/ro-cfg"
mkdir -p "$RO_HOME/$CID"
python3 - "$OWNER_HOME/$CID/keystore.json" "$RO_HOME/$CID/keystore.json" <<'PY'
import json, sys
ks = json.load(open(sys.argv[1]))
ks["write_secret"] = None
ks["role"] = "read"
json.dump(ks, open(sys.argv[2], "w"))
PY
RO_REPO="$WORK/ro-repo"
if CORD_GIT_HOME="$RO_HOME" "$CORD_BIN" clone "$CID" "$RO_REPO" >"$WORK/roclone.log" 2>&1; then
  pass "clone (read-only member) works"
else
  fail "clone (read-only member)"; cat "$WORK/roclone.log"
fi
echo "unauthorized change" >> "$RO_REPO/README.md"
git -C "$RO_REPO" commit -aq -m "ro edit" 2>/dev/null
if CORD_GIT_HOME="$RO_HOME" "$CORD_BIN" push --dir "$RO_REPO" >"$WORK/ropush.log" 2>&1; then
  fail "read-only push should have been refused"
else
  if grep -qi "read-only" "$WORK/ropush.log"; then
    pass "read-only push refused ($(tr -d '\n' <"$WORK/ropush.log" | tail -c 80))"
  else
    pass "read-only push refused"
  fi
fi

# --- scenario 6: concurrent-push CAS refusal -------------------------------
# Owner pushes a new commit (advances remote). A stale clone tries to push.
STALE="$WORK/stale-clone"
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" clone "$CID" "$STALE" >/dev/null 2>&1
# Advance the real remote from the primary repo.
echo "owner advance" >> "$REPO/README.md"
git -C "$REPO" commit -aq -m "owner advance"
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" push --dir "$REPO" >"$WORK/push2.log" 2>&1
# The stale clone's keystore base is now behind; but note both share OWNER_HOME
# keystore. To model divergent bases, push from the stale dir which carries the
# older manifest_prev via a copied keystore.
STALE_HOME="$WORK/stale-cfg"
mkdir -p "$STALE_HOME/$CID"
# Rewind the stale keystore's manifest_prev to the genesis (pre-advance) state.
python3 - "$OWNER_HOME/$CID/keystore.json" "$STALE_HOME/$CID/keystore.json" "$WORK/clone1.log" <<'PY'
import json, sys
ks = json.load(open(sys.argv[1]))
# The owner-clone log recorded the genesis 30641; force a stale base so the
# CAS check sees the remote has moved.
ks["manifest_prev"] = "0"*64
json.dump(ks, open(sys.argv[2], "w"))
PY
echo "stale change" >> "$STALE/README.md"
git -C "$STALE" commit -aq -m "stale edit" 2>/dev/null
if CORD_GIT_HOME="$STALE_HOME" "$CORD_BIN" push --dir "$STALE" >"$WORK/stalepush.log" 2>&1; then
  fail "stale push should have been refused (CAS)"
else
  if grep -qi "remote moved" "$WORK/stalepush.log"; then
    pass "concurrent-push CAS refused"
  else
    fail "stale push refused for wrong reason"; cat "$WORK/stalepush.log"
  fi
fi
# And after re-sync (force), it succeeds. Sleep past the 1-second granularity
# of created_at so the forced 30641 strictly supersedes the owner-advance one
# (addressable replacement tie-breaks equal timestamps by lowest id).
sleep 1.1
if CORD_GIT_HOME="$STALE_HOME" "$CORD_BIN" push --dir "$STALE" --force >"$WORK/forcepush.log" 2>&1; then
  pass "push --force after fork succeeds"
else
  fail "push --force"; cat "$WORK/forcepush.log"
fi

echo "==============================="
if [ "$FAILED" -eq 0 ]; then
  echo "E2E: ALL GREEN"
else
  echo "E2E: FAILURES ABOVE"
fi
exit "$FAILED"
