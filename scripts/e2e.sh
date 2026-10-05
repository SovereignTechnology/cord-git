#!/usr/bin/env bash
# CORD-git end-to-end test against a live GRASP-P server.
# Phase 3: create+push, clones, read-only refusal, CAS, pinning defense,
# rotate/revoke. Phase 4a: invite/join via a SEPARATE inbox relay (never the
# git node), invited writer push, invited reader read-only + server-side
# guestbook-key abuse rejection, offline invite handoff, roster;
# promote/demote/revoke lifecycle: promotion whisper + validation, standalone
# write-scope rotation, full refounding with the §3.3 widen -> wait -> rekey
# artifacts -> narrow sequencing, member folds (incl. forged-rekey rejection
# and revoked-member exclusion), and the fail-safe ordering abort.
# Crash-resume lifecycle (GitLab !12/!13/!14): pending-epoch persistence,
# partial-epoch fold refusal, 600-same-second-junk flood survival via
# until-pagination, byte-identical resume, owner fold-recovery. Multi-relay:
# partial-publish resume to a lagging node + staged-epoch-fork refusal.
# #collab: issues/PRs/comments as signed NIP-34 rumors on the #collab stream
# (member A files + comments, member B reads; a revoked member cannot read
# newly filed issues after the #collab key rolls). History retention
# (GitLab #21): a refounding must NOT truncate #collab/guestbook history for
# retained members, and invited newcomers receive the prior-key ring
# (GitHub-parity: removing a collaborator destroys nothing for everyone else).
# Exit 0 = all green.
set -uo pipefail

# Derive the tree layout from this script's own location so the defaults survive
# the tree being moved or checked out elsewhere. Explicit env vars still win.
_E2E_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORD_ROOT="$(cd "$_E2E_SCRIPT_DIR/.." && pwd)"   # .../cord-git
TREE_ROOT="$(cd "$CORD_ROOT/.." && pwd)"         # tree root holding cord-git/ and ref/

SERVER_BIN="${SERVER_BIN:-$TREE_ROOT/ref/ngit-grasp/target/release/ngit-grasp}"
CORD_BIN="${CORD_BIN:-$CORD_ROOT/target/release/cord-git}"
INBOX_BIN="${INBOX_BIN:-$CORD_ROOT/target/release/inbox-relay}"

# Fail fast naming the offender, instead of surfacing later as "server did not start".
for _bin_var in SERVER_BIN CORD_BIN INBOX_BIN; do
  if [ ! -x "${!_bin_var}" ]; then
    echo "FATAL: $_bin_var is not an executable file: ${!_bin_var}" >&2
    echo "       Build it (cargo build --release) or set $_bin_var explicitly." >&2
    exit 2
  fi
done

PORT="${PORT:-7361}"
INBOX_PORT="${INBOX_PORT:-7362}"
RELAY="ws://127.0.0.1:${PORT}"
SERVER="http://127.0.0.1:${PORT}"
INBOX="ws://127.0.0.1:${INBOX_PORT}"

WORK="$(mktemp -d)"
SRV_DATA="$WORK/srvdata"
mkdir -p "$SRV_DATA"
FAILED=0
SRV_PID=""
SRV2_PID=""
INBOX_PID=""

cleanup() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
  [ -n "$SRV2_PID" ] && kill "$SRV2_PID" 2>/dev/null
  [ -n "$INBOX_PID" ] && kill "$INBOX_PID" 2>/dev/null
  wait "$SRV_PID" 2>/dev/null
  wait "$SRV2_PID" 2>/dev/null
  wait "$INBOX_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILED=1; }

echo "=== workdir: $WORK ==="

# Git identity for the commits this script makes: its own global config. A run
# then neither depends on the caller's ~/.gitconfig (a CI VM has none, and
# every commit in a repository without its own identity fails there, mostly
# with stderr discarded) nor is changed by it (signing, hooks, templates).
# The per-repository identities set below still win.
export GIT_CONFIG_GLOBAL="$WORK/gitconfig"
git config --global user.name e2e
git config --global user.email e2e@example.com

# --- spawn server -----------------------------------------------------------
# Run from inside the data dir so the server's CWD-relative .relay-owner.nsec
# lands in the throwaway workdir (cleaned up), never the repo.
cd "$SRV_DATA" || exit 2
# Server phase-4b compat: the shipped default registration mode is whitelist
# (empty whitelist = reject all), and the write-rate / replacement-cadence
# limiters default on. This harness registers throwaway tenants at will and
# runs deliberate flood/rotation bursts, so it must pin open mode and disable
# both limiters (0 = unlimited); the server suite (exit26/27/33) covers the
# limiters themselves.
NGIT_DOMAIN="127.0.0.1:${PORT}" \
NGIT_BIND_ADDRESS="127.0.0.1:${PORT}" \
NGIT_DATABASE_BACKEND=memory \
NGIT_GRASP_P_REPOS_ENABLE=true \
NGIT_GRASP_P_REGISTRATION_MODE=open \
NGIT_GRASP_P_WRITE_RATE_CAPACITY=0 \
NGIT_GRASP_P_REGISTRATION_REPLACE_CAPACITY=0 \
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

# --- spawn the invitee inbox relay (separate from the git node) -------------
"$INBOX_BIN" "$INBOX_PORT" >"$WORK/inbox.log" 2>&1 &
INBOX_PID=$!
for _ in $(seq 1 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${INBOX_PORT}") 2>/dev/null; then
    exec 3>&- 3<&-
    break
  fi
  sleep 0.2
done
echo "inbox relay up on $INBOX_PORT (pid $INBOX_PID)"

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

# --- scenario 8: future-dated pinning attack --------------------------------
# A write key (still fully valid, pre-rotation) tries to publish a 30641 dated
# +2h. The server MUST reject it at admission (15-min future bound): admitted,
# it would EVICT the real latest 30641 from the relay DB (addressable
# replacement), a data-availability attack. The client freshness rule is the
# second layer (operator-injected events), proven in cord-core unit tests.
STALE_HEAD="$(git -C "$STALE" rev-parse HEAD)"
FORGE_OUT="$(CORD_GIT_ALLOW_DEBUG=1 CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" debug-forge-future-state "$CID" --ahead-secs 7200 --m "$(printf '0%.0s' $(seq 1 64))" 2>&1)"
if printf '%s' "$FORGE_OUT" | grep -q 'accepted=false'; then
  pass "server rejected the +2h forged state root (no eviction of the real latest)"
else
  fail "server admitted a +2h forged state root (would evict the real latest)"; echo "$FORGE_OUT"
fi
# The real latest (F1) must still be served and cloneable.
PIN_CLONE="$WORK/pin-clone"
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" clone "$CID" "$PIN_CLONE" >"$WORK/pinclone.log" 2>&1; then
  PIN_HEAD="$(git -C "$PIN_CLONE" rev-parse HEAD 2>/dev/null || echo none)"
  if [ "$PIN_HEAD" = "$STALE_HEAD" ]; then
    pass "real latest survived the pinning attempt (clone round-trips)"
  else
    fail "latest state root was evicted by the forge (head=$PIN_HEAD expected=$STALE_HEAD)"
  fi
else
  fail "clone failed after pinning attempt"; cat "$WORK/pinclone.log"
fi
# And the server-side defense: a +2day forgery is rejected at admission.
FORGE2_OUT="$(CORD_GIT_ALLOW_DEBUG=1 CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" debug-forge-future-state "$CID" --ahead-secs 200000 --m "$(printf '0%.0s' $(seq 1 64))" 2>&1)"
if printf '%s' "$FORGE2_OUT" | grep -q 'accepted=false'; then
  pass "server rejected the +2day forged state root (future bound)"
else
  fail "server admitted a +2day forged state root"; echo "$FORGE2_OUT"
fi

# --- scenario 7: revocation via rotate -------------------------------------
# A "member" holds a full copy of the owner secrets. The owner rotates; the
# member (old secrets) must then be unable to push OR read new content.
MEMBER_HOME="$WORK/member-cfg"
mkdir -p "$MEMBER_HOME/$CID"
cp "$OWNER_HOME/$CID/keystore.json" "$MEMBER_HOME/$CID/keystore.json"
MEMBER_REPO="$WORK/member-repo"
CORD_GIT_HOME="$MEMBER_HOME" "$CORD_BIN" clone "$CID" "$MEMBER_REPO" >/dev/null 2>&1
sleep 1.1
# 7a: rotating from a STALE checkout must be REFUSED (freshness guard — the
# scenario-6 force push moved the remote past the original owner repo).
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" rotate --dir "$REPO" >"$WORK/rotate-stale.log" 2>&1; then
  fail "rotate from a stale checkout should have been refused"
else
  if grep -qi "refusing to rotate" "$WORK/rotate-stale.log"; then
    pass "stale-checkout rotate refused by freshness guard"
  else
    fail "stale rotate failed for wrong reason"; cat "$WORK/rotate-stale.log"
  fi
fi
# 7b: re-sync (clone fresh), then rotate from the up-to-date checkout.
REPO_FRESH="$WORK/owner-fresh"
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" clone "$CID" "$REPO_FRESH" >/dev/null 2>&1
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" rotate --dir "$REPO_FRESH" >"$WORK/rotate.log" 2>&1; then
  pass "owner rotate/revoke succeeded ($(sed -n 's/.*30641 id: //p' "$WORK/rotate.log" | cut -c1-12)…)"
else
  fail "owner rotate/revoke"; cat "$WORK/rotate.log"
fi
# Owner pushes fresh content under the new secrets.
sleep 1.1
echo "post-revocation secret content" >> "$REPO_FRESH/README.md"
git -C "$REPO_FRESH" commit -aq -m "after revocation"
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" push --dir "$REPO_FRESH" >"$WORK/push3.log" 2>&1

# Removed member (old secrets) tries to push → server rejects (write key freed).
echo "member sneaky change" >> "$MEMBER_REPO/README.md"
git -C "$MEMBER_REPO" commit -aq -m "member edit" 2>/dev/null
if CORD_GIT_HOME="$MEMBER_HOME" "$CORD_BIN" push --dir "$MEMBER_REPO" --force >"$WORK/memberpush.log" 2>&1; then
  fail "revoked member push should have been rejected by the server"
else
  if grep -qiE 'registered write key|rejected|restricted' "$WORK/memberpush.log"; then
    pass "revoked member push rejected server-side"
  else
    fail "revoked member push failed for wrong reason"; cat "$WORK/memberpush.log"
  fi
fi

# Removed member (old #state key) tries to read the new content → cannot decrypt.
MEMBER_RECLONE="$WORK/member-reclone"
if CORD_GIT_HOME="$MEMBER_HOME" "$CORD_BIN" clone "$CID" "$MEMBER_RECLONE" >"$WORK/memberclone.log" 2>&1; then
  # If it "succeeds", the new content must NOT be present (they only see old).
  if grep -q "post-revocation" "$MEMBER_RECLONE/README.md" 2>/dev/null; then
    fail "revoked member could read post-revocation content"
  else
    pass "revoked member cannot read post-revocation content (stale view only)"
  fi
else
  if grep -qiE 'aead|decrypt|mismatch|wrong key' "$WORK/memberclone.log"; then
    pass "revoked member clone fails to decrypt new manifest"
  else
    fail "revoked member clone failed for wrong reason"; cat "$WORK/memberclone.log"
  fi
fi

# --- Phase 4a: invite/join over the invitee's inbox relay -------------------
# Actors: writer (push role), reader (read role), reader2 (offline handoff).
WRITER_KEYS="$("$CORD_BIN" keygen)"
WRITER_NSEC="$(printf '%s\n' "$WRITER_KEYS" | sed -n 's/^nsec: //p')"
WRITER_PUB="$(printf '%s\n' "$WRITER_KEYS" | sed -n 's/^pubkey: //p')"
READER_KEYS="$("$CORD_BIN" keygen)"
READER_NSEC="$(printf '%s\n' "$READER_KEYS" | sed -n 's/^nsec: //p')"
READER_PUB="$(printf '%s\n' "$READER_KEYS" | sed -n 's/^pubkey: //p')"
READER2_KEYS="$("$CORD_BIN" keygen)"
READER2_NSEC="$(printf '%s\n' "$READER2_KEYS" | sed -n 's/^nsec: //p')"
READER2_PUB="$(printf '%s\n' "$READER2_KEYS" | sed -n 's/^pubkey: //p')"
if [ -n "$WRITER_NSEC" ] && [ -n "$READER_NSEC" ] && [ -n "$READER2_NSEC" ]; then
  pass "keygen produced member identities"
else
  fail "keygen"; printf '%s\n' "$WRITER_KEYS"
fi

# 15: NORMATIVE — an invite aimed at the git node itself must be refused.
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" invite "$WRITER_PUB" --write --via "$RELAY" --dir "$REPO_FRESH" >"$WORK/invite-gitnode.log" 2>&1; then
  fail "invite to the git node should have been refused"
else
  if grep -qi "refusing to deliver an invite to a git node" "$WORK/invite-gitnode.log"; then
    pass "invite to the git node refused (inbox relays only)"
  else
    fail "git-node invite refused for wrong reason"; cat "$WORK/invite-gitnode.log"
  fi
fi

# 16: owner invites the writer (push role) via the inbox relay.
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" invite "$WRITER_PUB" --write --via "$INBOX" --dir "$REPO_FRESH" >"$WORK/invite-writer.log" 2>&1; then
  pass "invite (write) delivered to the inbox relay"
else
  fail "invite (write)"; cat "$WORK/invite-writer.log"
fi

# 17: writer joins from the inbox relay (keystore import + guestbook Join).
WRITER_HOME="$WORK/writer-cfg"
if CORD_GIT_HOME="$WRITER_HOME" "$CORD_BIN" join --nsec "$WRITER_NSEC" --relay "$INBOX" >"$WORK/join-writer.log" 2>&1 \
   && grep -q "joined community $CID" "$WORK/join-writer.log"; then
  pass "writer join (invite consumed, guestbook join published)"
else
  fail "writer join"; cat "$WORK/join-writer.log"
fi

# 18: invited writer clones and pushes end-to-end.
WRITER_REPO="$WORK/writer-repo"
OWNER_HEAD="$(git -C "$REPO_FRESH" rev-parse HEAD)"
if CORD_GIT_HOME="$WRITER_HOME" "$CORD_BIN" clone "$CID" "$WRITER_REPO" >"$WORK/writer-clone.log" 2>&1 \
   && [ "$(git -C "$WRITER_REPO" rev-parse HEAD 2>/dev/null)" = "$OWNER_HEAD" ]; then
  pass "invited writer clone matches owner HEAD"
else
  fail "invited writer clone"; cat "$WORK/writer-clone.log"
fi
git -C "$WRITER_REPO" config user.email writer@example.com
git -C "$WRITER_REPO" config user.name writer
echo "writer contribution" >> "$WRITER_REPO/README.md"
git -C "$WRITER_REPO" commit -aq -m "writer contribution"
sleep 1.1
if CORD_GIT_HOME="$WRITER_HOME" "$CORD_BIN" push --dir "$WRITER_REPO" >"$WORK/writer-push.log" 2>&1; then
  pass "invited writer push succeeds"
else
  fail "invited writer push"; cat "$WORK/writer-push.log"
fi

# 19: owner invites the reader (read role); reader joins and clones.
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" invite "$READER_PUB" --via "$INBOX" --dir "$REPO_FRESH" >"$WORK/invite-reader.log" 2>&1
READER_HOME="$WORK/reader-cfg"
READER_REPO="$WORK/reader-repo"
if CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" join --nsec "$READER_NSEC" --relay "$INBOX" >"$WORK/join-reader.log" 2>&1 \
   && CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" clone "$CID" "$READER_REPO" >"$WORK/reader-clone.log" 2>&1 \
   && grep -q "writer contribution" "$READER_REPO/README.md"; then
  pass "invited reader join+clone sees the writer's push"
else
  fail "invited reader join/clone"; cat "$WORK/join-reader.log" "$WORK/reader-clone.log" 2>/dev/null
fi

# 20: reader cannot push (no write_secret in a read invite).
git -C "$READER_REPO" config user.email reader@example.com 2>/dev/null
git -C "$READER_REPO" config user.name reader 2>/dev/null
echo "reader sneaky" >> "$READER_REPO/README.md"
git -C "$READER_REPO" commit -aq -m "reader edit" 2>/dev/null
if CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" push --dir "$READER_REPO" >"$WORK/reader-push.log" 2>&1; then
  fail "invited reader push should have been refused"
else
  if grep -qi "read-only" "$WORK/reader-push.log"; then
    pass "invited reader push refused (no write_secret)"
  else
    fail "reader push refused for wrong reason"; cat "$WORK/reader-push.log"
  fi
fi

# 21: reader abusing the derived guestbook (aux) key is rejected server-side —
# blob PUT and 30641 both require a registered WRITE key.
ATTACK_OUT="$(CORD_GIT_ALLOW_DEBUG=1 CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" debug-reader-attack "$CID" 2>&1)"
if printf '%s' "$ATTACK_OUT" | grep -q 'put_rejected=true'; then
  pass "reader blob PUT rejected server-side (aux key cannot write blobs)"
else
  fail "reader blob PUT was not rejected"; echo "$ATTACK_OUT"
fi
if printf '%s' "$ATTACK_OUT" | grep -q 'state_rejected=true'; then
  pass "reader 30641 rejected server-side (aux key cannot publish state roots)"
else
  fail "reader 30641 was not rejected"; echo "$ATTACK_OUT"
fi

# 22: offline handoff — invite written to a file, joined with --file.
INVITE_FILE="$WORK/invite-reader2.json"
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" invite "$READER2_PUB" --via "$INBOX" --out "$INVITE_FILE" --dir "$REPO_FRESH" >"$WORK/invite-reader2.log" 2>&1
READER2_HOME="$WORK/reader2-cfg"
READER2_REPO="$WORK/reader2-repo"
if CORD_GIT_HOME="$READER2_HOME" "$CORD_BIN" join --nsec "$READER2_NSEC" --file "$INVITE_FILE" >"$WORK/join-reader2.log" 2>&1 \
   && CORD_GIT_HOME="$READER2_HOME" "$CORD_BIN" clone "$CID" "$READER2_REPO" >"$WORK/reader2-clone.log" 2>&1 \
   && grep -q "writer contribution" "$READER2_REPO/README.md"; then
  pass "offline invite file handoff join+clone works"
else
  fail "offline invite handoff"; cat "$WORK/join-reader2.log" "$WORK/reader2-clone.log" 2>/dev/null
fi

# 23: roster — owner sees the grants; guestbook joins are verifiable and
# include the writer's identity (inner rumor signed by the member npub).
ROSTER_OUT="$(CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" roster "$CID" 2>&1)"
if printf '%s' "$ROSTER_OUT" | grep -q "$WRITER_PUB" \
   && printf '%s' "$ROSTER_OUT" | grep -q "$READER_PUB" \
   && printf '%s' "$ROSTER_OUT" | grep -q "$READER2_PUB"; then
  pass "roster lists all three grants"
else
  fail "roster grants missing"; echo "$ROSTER_OUT"
fi
JOINS="$(printf '%s\n' "$ROSTER_OUT" | grep -c '^  join ')"
if [ "$JOINS" -ge 4 ] && printf '%s' "$ROSTER_OUT" | grep -q "join $WRITER_PUB"; then
  pass "guestbook joins verified (owner genesis + 3 members)"
else
  fail "guestbook joins missing (got $JOINS)"; echo "$ROSTER_OUT"
fi

# --- Phase 4a: #collab issues/PRs (signed NIP-34 rumors on the #collab stream)
# Member A (writer) files an issue + comment; member B (reader) lists and reads
# them — inner rumors are signed by the author identity, sealed under the
# #collab key, and carried in aux-signed 3359 stream wraps.
ISSUE_OUT="$(CORD_GIT_HOME="$WRITER_HOME" CORD_GIT_NSEC="$WRITER_NSEC" "$CORD_BIN" issue new "login crashes on empty password" --body "steps: submit an empty form" --dir "$WRITER_REPO" 2>&1)"
ISSUE_ID="$(printf '%s\n' "$ISSUE_OUT" | sed -n 's/^filed issue //p')"
if [ -n "$ISSUE_ID" ]; then
  pass "member A filed a #collab issue ($(printf '%s' "$ISSUE_ID" | cut -c1-12)…)"
else
  fail "issue new"; echo "$ISSUE_OUT"
fi
if CORD_GIT_HOME="$WRITER_HOME" CORD_GIT_NSEC="$WRITER_NSEC" "$CORD_BIN" issue comment "$ISSUE_ID" --body "i have a fix in progress" --dir "$WRITER_REPO" >"$WORK/issue-comment.log" 2>&1; then
  pass "member A commented on the issue"
else
  fail "issue comment"; cat "$WORK/issue-comment.log"
fi
# member B (reader) lists the issue and reads its body + comment.
LIST_OUT="$(CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" issue list --dir "$READER_REPO" 2>&1)"
if printf '%s' "$LIST_OUT" | grep -q "login crashes on empty password"; then
  pass "member B lists the issue filed by member A"
else
  fail "member B issue list"; echo "$LIST_OUT"
fi
SHOW_OUT="$(CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" issue show "$ISSUE_ID" --dir "$READER_REPO" 2>&1)"
if printf '%s' "$SHOW_OUT" | grep -q "steps: submit an empty form" \
   && printf '%s' "$SHOW_OUT" | grep -q "i have a fix in progress"; then
  pass "member B reads the issue body + comment (rumor signatures verified)"
else
  fail "member B issue show"; echo "$SHOW_OUT"
fi
# member A submits a PR (patch series from a revision range); member B lists it.
PR_OUT="$(CORD_GIT_HOME="$WRITER_HOME" CORD_GIT_NSEC="$WRITER_NSEC" "$CORD_BIN" pr new --range "HEAD~1..HEAD" --subject "add writer contribution" --dir "$WRITER_REPO" 2>&1)"
PR_ID="$(printf '%s\n' "$PR_OUT" | sed -n 's/^submitted PR //p')"
if [ -n "$PR_ID" ] && CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" pr list --dir "$READER_REPO" 2>&1 | grep -q "add writer contribution"; then
  pass "member A submitted a PR; member B lists it"
else
  fail "pr new/list"; echo "$PR_OUT"; CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" pr list --dir "$READER_REPO" 2>&1
fi

# 23b: GitLab #21 — a member who joins AFTER issues exist (same epoch, no
# rotation involved) must read the existing back-history immediately.
LATE_KEYS="$("$CORD_BIN" keygen)"
LATE_NSEC="$(printf '%s\n' "$LATE_KEYS" | sed -n 's/^nsec: //p')"
LATE_PUB="$(printf '%s\n' "$LATE_KEYS" | sed -n 's/^pubkey: //p')"
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" invite "$LATE_PUB" --via "$INBOX" --dir "$REPO_FRESH" >"$WORK/invite-late.log" 2>&1
LATE_HOME="$WORK/late-cfg"
LATE_REPO="$WORK/late-repo"
if CORD_GIT_HOME="$LATE_HOME" "$CORD_BIN" join --nsec "$LATE_NSEC" --relay "$INBOX" >"$WORK/join-late.log" 2>&1 \
   && CORD_GIT_HOME="$LATE_HOME" "$CORD_BIN" clone "$CID" "$LATE_REPO" >"$WORK/late-clone.log" 2>&1 \
   && CORD_GIT_HOME="$LATE_HOME" "$CORD_BIN" issue list --dir "$LATE_REPO" 2>&1 | grep -q "login crashes on empty password"; then
  pass "same-epoch late joiner reads pre-existing issues"
else
  fail "late joiner cannot read pre-existing issues"; CORD_GIT_HOME="$LATE_HOME" "$CORD_BIN" issue list --dir "$LATE_REPO" 2>&1
fi

# --- Phase 4a: promote / demote / revoke with §3.3 sequencing ---------------

# 24: promotion must ride the member's inbox relay, never the git node.
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" promote "$READER_PUB" --via "$RELAY" --dir "$REPO_FRESH" >"$WORK/promote-gitnode.log" 2>&1; then
  fail "promotion to the git node should have been refused"
else
  if grep -qi "refusing to deliver a promotion to a git node" "$WORK/promote-gitnode.log"; then
    pass "promotion to the git node refused (inbox relays only)"
  else
    fail "git-node promotion refused for wrong reason"; cat "$WORK/promote-gitnode.log"
  fi
fi

# 25: owner promotes the reader (grant + write_secret whisper); reader accepts
# (validating the secret against the live 30640) and can push.
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" promote "$READER_PUB" --via "$INBOX" --dir "$REPO_FRESH" >"$WORK/promote-reader.log" 2>&1 \
   && CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" promote-accept --nsec "$READER_NSEC" --relay "$INBOX" >"$WORK/promote-accept.log" 2>&1 \
   && grep -q "push role active" "$WORK/promote-accept.log"; then
  pass "promote delivered + accepted (secret validated against live 30640)"
else
  fail "promote/promote-accept"; cat "$WORK/promote-reader.log" "$WORK/promote-accept.log" 2>/dev/null
fi
READER_WREPO="$WORK/reader-write-repo"
sleep 1.1
if CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" clone "$CID" "$READER_WREPO" >/dev/null 2>&1; then :; fi
git -C "$READER_WREPO" config user.email reader@example.com
git -C "$READER_WREPO" config user.name reader
echo "promoted reader contribution" >> "$READER_WREPO/README.md"
git -C "$READER_WREPO" commit -aq -m "promoted reader contribution"
if CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" push --dir "$READER_WREPO" >"$WORK/reader-wpush.log" 2>&1; then
  pass "promoted reader push succeeds"
else
  fail "promoted reader push"; cat "$WORK/reader-wpush.log"
fi

# 26: owner demotes the reader — standalone write-scope rotation, NO
# refounding. Runs from a fresh checkout (freshness guard).
OWNER2="$WORK/owner-demote"
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" clone "$CID" "$OWNER2" >/dev/null 2>&1
sleep 1.1
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" demote "$READER_PUB" --dir "$OWNER2" >"$WORK/demote.log" 2>&1; then
  pass "demote (write-scope rotation) succeeded"
else
  fail "demote"; cat "$WORK/demote.log"
fi
# Demoted reader: blob PUT is rejected server-side (their write key was freed).
echo "demoted sneaky" >> "$READER_WREPO/README.md"
git -C "$READER_WREPO" commit -aq -m "demoted edit" 2>/dev/null
if CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" push --dir "$READER_WREPO" --force >"$WORK/demoted-push.log" 2>&1; then
  fail "demoted reader push should have been rejected"
else
  if grep -qiE 'registered write key|rejected|restricted' "$WORK/demoted-push.log"; then
    pass "demoted reader push rejected server-side"
  else
    fail "demoted reader push failed for wrong reason"; cat "$WORK/demoted-push.log"
  fi
fi
# Retained writer folds the write-scope rekey and can push again.
if CORD_GIT_HOME="$WRITER_HOME" "$CORD_BIN" fold "$CID" --nsec "$WRITER_NSEC" >"$WORK/writer-fold.log" 2>&1 \
   && grep -q "folded 1 rotation" "$WORK/writer-fold.log"; then
  pass "retained writer folded the write-scope rekey"
else
  fail "writer fold"; cat "$WORK/writer-fold.log"
fi
WRITER2="$WORK/writer-repo2"
CORD_GIT_HOME="$WRITER_HOME" "$CORD_BIN" clone "$CID" "$WRITER2" >/dev/null 2>&1
git -C "$WRITER2" config user.email writer@example.com
git -C "$WRITER2" config user.name writer
echo "post-demote writer work" >> "$WRITER2/README.md"
git -C "$WRITER2" commit -aq -m "post-demote writer work"
sleep 1.1
if CORD_GIT_HOME="$WRITER_HOME" "$CORD_BIN" push --dir "$WRITER2" >"$WORK/writer-push2.log" 2>&1; then
  pass "retained writer push succeeds after fold"
else
  fail "retained writer push after fold"; cat "$WORK/writer-push2.log"
fi
# Demoted reader keeps READ access (no refounding): a fresh clone still works.
READER_RCLONE="$WORK/reader-postdemote"
if CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" clone "$CID" "$READER_RCLONE" >"$WORK/reader-rclone.log" 2>&1 \
   && grep -q "post-demote writer work" "$READER_RCLONE/README.md"; then
  pass "demoted reader still reads (demotion is not removal)"
else
  fail "demoted reader read"; cat "$WORK/reader-rclone.log" 2>/dev/null
fi

# 27: the (about-to-be-revoked) writer pre-plants FORGED rekeys at the
# next-epoch addresses. GitLab !13: between rotations those addresses are NOT
# in the narrow's aux set, so the server must REFUSE the wraps at admission —
# the flood/forgery window is now just the seconds-long widen->narrow window.
FORGE_REKEY_OUT="$(CORD_GIT_ALLOW_DEBUG=1 CORD_GIT_HOME="$WRITER_HOME" "$CORD_BIN" debug-forge-rekey "$CID" --victim "$READER_PUB" 2>&1)"
echo "$FORGE_REKEY_OUT" | sed 's/^/  forge: /'
if printf '%s' "$FORGE_REKEY_OUT" | grep -q 'forged_state_rekey_admitted=false' \
   && printf '%s' "$FORGE_REKEY_OUT" | grep -q 'forged_write_rekey_admitted=false'; then
  pass "next-epoch rekey addresses not admitted between rotations (forgeries rejected at admission)"
else
  fail "next-epoch rekey addresses were admitted outside a rotation window"; echo "$FORGE_REKEY_OUT"
fi

# 28: owner revokes the writer — banlist + refounding + §3.3 sequencing.
OWNER3="$WORK/owner-revoke"
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" clone "$CID" "$OWNER3" >/dev/null 2>&1
sleep 1.1
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" revoke "$WRITER_PUB" --dir "$OWNER3" >"$WORK/revoke.log" 2>&1; then
  pass "revoke (refounding + sequenced rotation) succeeded"
else
  fail "revoke"; cat "$WORK/revoke.log"
fi
# Post-revocation content the removed writer must never read.
sleep 1.1
echo "post-revoke secret" >> "$OWNER3/README.md"
git -C "$OWNER3" commit -aq -m "post-revoke"
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" push --dir "$OWNER3" >"$WORK/owner-push4.log" 2>&1
# Revoked writer: blob PUT / state root rejected server-side.
echo "revoked writer sneaky" >> "$WRITER2/README.md"
git -C "$WRITER2" commit -aq -m "revoked edit" 2>/dev/null
if CORD_GIT_HOME="$WRITER_HOME" "$CORD_BIN" push --dir "$WRITER2" --force >"$WORK/revoked-push.log" 2>&1; then
  fail "revoked writer push should have been rejected"
else
  if grep -qiE 'registered write key|rejected|restricted' "$WORK/revoked-push.log"; then
    pass "revoked writer push (blob PUT) rejected server-side"
  else
    fail "revoked writer push failed for wrong reason"; cat "$WORK/revoked-push.log"
  fi
fi
# Revoked writer cannot decrypt the new epoch's manifests.
WRITER_RECLONE="$WORK/writer-reclone"
if CORD_GIT_HOME="$WRITER_HOME" "$CORD_BIN" clone "$CID" "$WRITER_RECLONE" >"$WORK/writer-reclone.log" 2>&1; then
  if grep -q "post-revoke" "$WRITER_RECLONE/README.md" 2>/dev/null; then
    fail "revoked writer could read post-revocation content"
  else
    pass "revoked writer cannot read post-revocation content (stale view only)"
  fi
else
  if grep -qiE 'aead|decrypt|mismatch|wrong key' "$WORK/writer-reclone.log"; then
    pass "revoked writer clone fails to decrypt the new-epoch manifest"
  else
    fail "revoked writer clone failed for wrong reason"; cat "$WORK/writer-reclone.log"
  fi
fi
# Revoked writer's fold is refused: the refounding carries no slot for them.
if CORD_GIT_HOME="$WRITER_HOME" "$CORD_BIN" fold "$CID" --nsec "$WRITER_NSEC" >"$WORK/writer-fold2.log" 2>&1; then
  fail "revoked writer fold should have reported exclusion"
else
  if grep -qi "excluded" "$WORK/writer-fold2.log"; then
    pass "revoked writer fold reports exclusion (no refounding slot)"
  else
    fail "revoked writer fold failed for wrong reason"; cat "$WORK/writer-fold2.log"
  fi
fi
# Retained reader folds BOTH epochs (demote + refounding), rejecting the
# planted forged rekeys along the way, and reads the post-revoke content.
if CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" fold "$CID" --nsec "$READER_NSEC" >"$WORK/reader-fold.log" 2>&1 \
   && grep -q "folded 2 rotation" "$WORK/reader-fold.log"; then
  pass "retained reader folded demote + refounding epochs"
else
  fail "reader fold"; cat "$WORK/reader-fold.log"
fi
READER_POSTREVOKE="$WORK/reader-postrevoke"
if CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" clone "$CID" "$READER_POSTREVOKE" >"$WORK/reader-prclone.log" 2>&1 \
   && grep -q "post-revoke secret" "$READER_POSTREVOKE/README.md"; then
  pass "retained reader reads post-revoke content (forged rekeys rejected)"
else
  fail "retained reader post-revoke read"; cat "$WORK/reader-prclone.log" 2>/dev/null
fi
# Roster fold shows the ban.
ROSTER2_OUT="$(CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" roster "$CID" 2>&1)"
if printf '%s' "$ROSTER2_OUT" | grep -q "banned $WRITER_PUB"; then
  pass "roster records the banlist entry"
else
  fail "roster missing the ban"; echo "$ROSTER2_OUT"
fi
# GitLab #21: guestbook join history survives the refounding too — the joins
# were recorded under the PRE-revoke stream key (shared derivation with
# #collab), and a revoke must not erase who ever joined.
if printf '%s' "$ROSTER2_OUT" | grep -q "join $WRITER_PUB"; then
  pass "roster join history survives the refounding (prior-stream-key ring)"
else
  fail "refounding truncated the guestbook join history"; echo "$ROSTER2_OUT"
fi
# 28c: after the REVOKE narrow, the next epoch's rekey addresses are again
# unlisted — forgeries at them must be rejected at admission (binds the !13
# listing change at the revoke narrow, not just the demote narrow).
FORGE_AFTER_REVOKE="$(CORD_GIT_ALLOW_DEBUG=1 CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" debug-forge-rekey "$CID" --victim "$WRITER_PUB" 2>&1)"
if printf '%s' "$FORGE_AFTER_REVOKE" | grep -q 'forged_state_rekey_admitted=false' \
   && printf '%s' "$FORGE_AFTER_REVOKE" | grep -q 'forged_write_rekey_admitted=false'; then
  pass "post-revoke narrow: next-epoch rekey addresses not admitted"
else
  fail "revoke narrow still lists next-epoch rekey addresses"; echo "$FORGE_AFTER_REVOKE"
fi

# 28b: #collab exclusion — a retained member files a NEW issue under the rolled
# #collab key; retained members read it, but the REVOKED writer (holding the
# old #collab key) cannot even see it (old stream key + old seal key).
POST_ISSUE_OUT="$(CORD_GIT_HOME="$READER_HOME" CORD_GIT_NSEC="$READER_NSEC" "$CORD_BIN" issue new "post-revoke security note" --body "rotated secrets are live" --dir "$READER_POSTREVOKE" 2>&1)"
POST_ISSUE_ID="$(printf '%s\n' "$POST_ISSUE_OUT" | sed -n 's/^filed issue //p')"
if [ -n "$POST_ISSUE_ID" ]; then
  pass "retained member filed a post-revocation issue (new epoch/#collab key)"
else
  fail "post-revoke issue new"; echo "$POST_ISSUE_OUT"
fi
# Retained owner reads it (positive control).
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" issue list --dir "$OWNER3" 2>&1 | grep -q "post-revoke security note"; then
  pass "retained owner reads the post-revocation issue"
else
  fail "retained owner cannot read post-revoke issue"; CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" issue list --dir "$OWNER3" 2>&1
fi
# 28b-2: GitLab #21 FIX TARGET — the refounding must NOT truncate history for
# retained members (GitHub parity: removing a collaborator destroys nothing
# for everyone else). Pre-fix this fails: the rolled key orphaned old wraps.
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" issue list --dir "$OWNER3" 2>&1 | grep -q "login crashes on empty password"; then
  pass "retained owner still reads the PRE-revoke issue (history survived the refounding)"
else
  fail "refounding truncated the owner's #collab history"
  CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" issue list --dir "$OWNER3" 2>&1
fi
# ...and the retained (folded) reader keeps the full pre-revoke thread.
if CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" issue show "$ISSUE_ID" --dir "$READER_POSTREVOKE" 2>&1 | grep -q "i have a fix in progress"; then
  pass "retained reader still reads the pre-revoke issue thread after folding"
else
  fail "refounding truncated the reader's #collab history"
  CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" issue show "$ISSUE_ID" --dir "$READER_POSTREVOKE" 2>&1
fi
# Revoked writer (old #collab key) cannot read the newly filed issue.
REVOKED_LIST="$(CORD_GIT_HOME="$WRITER_HOME" "$CORD_BIN" issue list --dir "$WRITER2" 2>&1)"
if printf '%s' "$REVOKED_LIST" | grep -q "post-revoke security note"; then
  fail "revoked member could read a newly filed issue"
else
  pass "revoked member cannot read newly filed issues (#collab key rolled)"
fi

# 28b-3: GitLab #21 — GitHub parity for NEWCOMERS: a member invited AFTER the
# revoke receives the prior-key ring inside the invite bundle and reads the
# pre-revoke back-history, like a new collaborator on a private GitHub repo.
NEW_KEYS="$("$CORD_BIN" keygen)"
NEW_NSEC="$(printf '%s\n' "$NEW_KEYS" | sed -n 's/^nsec: //p')"
NEW_PUB="$(printf '%s\n' "$NEW_KEYS" | sed -n 's/^pubkey: //p')"
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" invite "$NEW_PUB" --via "$INBOX" --dir "$OWNER3" >"$WORK/invite-new.log" 2>&1
NEW_HOME="$WORK/newcomer-cfg"
NEW_REPO="$WORK/newcomer-repo"
if CORD_GIT_HOME="$NEW_HOME" "$CORD_BIN" join --nsec "$NEW_NSEC" --relay "$INBOX" >"$WORK/join-new.log" 2>&1 \
   && CORD_GIT_HOME="$NEW_HOME" "$CORD_BIN" clone "$CID" "$NEW_REPO" >"$WORK/new-clone.log" 2>&1; then
  NEW_LIST="$(CORD_GIT_HOME="$NEW_HOME" "$CORD_BIN" issue list --dir "$NEW_REPO" 2>&1)"
  if printf '%s' "$NEW_LIST" | grep -q "login crashes on empty password" \
     && printf '%s' "$NEW_LIST" | grep -q "post-revoke security note"; then
    pass "post-revoke newcomer reads BOTH pre- and post-revoke history (invite hand-back)"
  else
    fail "post-revoke newcomer is missing history"; echo "$NEW_LIST"
  fi
else
  fail "post-revoke newcomer join/clone"; cat "$WORK/join-new.log" "$WORK/new-clone.log" 2>/dev/null
fi

# 28d: verify-round F-B — a member cross-alias SQUATS the NEXT epoch's
# state-scope rekey address (registered under their own fresh alias, BACKDATED
# so it wins the post-!11 §3.2 merge — an honest-created_at squat would now
# lose to the live+1 widen and be evicted), so every upcoming rotation's widen
# hits "write key already registered". The rotations MUST still complete via
# the squat-tolerant minimal widen.
SQUAT_OUT="$(CORD_GIT_ALLOW_DEBUG=1 CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" debug-squat-rekey "$CID" --scope state 2>&1)"
echo "$SQUAT_OUT" | sed 's/^/  squat: /'
if printf '%s' "$SQUAT_OUT" | grep -q 'accepted=true'; then
  pass "cross-alias squat planted on the state-scope rekey address"
else
  fail "squat not admitted"; echo "$SQUAT_OUT"
fi

# 29: §3.3 ordering — when 30640' (widen) cannot be confirmed on ALL nodes,
# the client refuses to publish ANY refounding artifact and fails safely.
ORDER_HOME="$WORK/order-cfg"
mkdir -p "$ORDER_HOME/$CID"
python3 - "$OWNER_HOME/$CID/keystore.json" "$ORDER_HOME/$CID/keystore.json" <<'PY'
import json, sys
ks = json.load(open(sys.argv[1]))
ks["relays"] = ks["relays"] + ["ws://127.0.0.1:1"]  # unreachable second node
json.dump(ks, open(sys.argv[2], "w"))
PY
ORDER_REPO="$WORK/order-repo"
CORD_GIT_HOME="$ORDER_HOME" "$CORD_BIN" clone "$CID" "$ORDER_REPO" >/dev/null 2>&1
if CORD_GIT_HOME="$ORDER_HOME" "$CORD_BIN" revoke "$READER2_PUB" --dir "$ORDER_REPO" >"$WORK/order-revoke.log" 2>&1; then
  fail "revoke should have refused: widen not confirmable on all nodes"
else
  if grep -qi "refusing to publish any refounding artifact" "$WORK/order-revoke.log"; then
    pass "ordering: no refounding artifact before 30640-prime acceptance on ALL nodes"
  else
    fail "ordering revoke failed for wrong reason"; cat "$WORK/order-revoke.log"
  fi
fi
# Fail-safe: the aborted widen left the repo fully functional on old secrets.
sleep 1.1
echo "after aborted revoke" >> "$OWNER3/README.md"
git -C "$OWNER3" commit -aq -m "after aborted revoke"
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" push --dir "$OWNER3" >"$WORK/owner-push5.log" 2>&1; then
  pass "aborted revoke is safe: owner still pushes with current secrets"
else
  fail "owner push after aborted revoke"; cat "$WORK/owner-push5.log"
fi

# --- 30: GitLab !12/!13/!14 — crash-resume, partial-epoch fold refusal, flood
# survival, owner fold-recovery ---------------------------------------------
# 30a: stage an up-to-date owner checkout + back up the pre-rotation keystore
# (the backup simulates owner state loss for the fold-recovery test below).
OWNER4="$WORK/owner-resume"
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" clone "$CID" "$OWNER4" >/dev/null 2>&1
cp "$OWNER_HOME/$CID/keystore.json" "$WORK/owner-keystore-pre-epoch3.json"
sleep 1.1
# 30b: crash-simulation — the revoke aborts right after publishing the
# state+collab rekeys (CORD_GIT_DEBUG_ABORT_AFTER). The write-scope rekey is
# NOT published yet; the pending-epoch file MUST exist (persist-before-publish).
if CORD_GIT_ALLOW_DEBUG=1 CORD_GIT_DEBUG_ABORT_AFTER=rekey:collab \
   CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" revoke "$READER2_PUB" --dir "$OWNER4" >"$WORK/revoke-abort.log" 2>&1; then
  fail "debug-abort revoke should have failed mid-sequence"
else
  if grep -qi "debug abort after rekey:collab" "$WORK/revoke-abort.log" \
     && [ -f "$OWNER_HOME/$CID/pending-epoch.json" ]; then
    pass "crash mid-rotation: pending epoch persisted before publish (write rekey unpublished)"
  else
    fail "crash mid-rotation"; cat "$WORK/revoke-abort.log"
  fi
fi
# The state-scope squat forced the widen through the squat-tolerant minimal
# variant (verify-round F-B) and the collab address was re-added on demand.
if grep -qi "without the rekey addresses" "$WORK/revoke-abort.log"; then
  pass "squat-tolerant minimal widen engaged (rotation unwedged by the squat)"
else
  fail "minimal-widen fallback did not engage"; cat "$WORK/revoke-abort.log"
fi
# 30b-2: verify-round F6 — the pre-mint fork guard: a DIFFERENT owner machine
# (keystore copy WITHOUT the pending file) trying the same revoke while the
# first rotation's rekeys are live must be REFUSED — no rival rekey set.
GUARD_HOME="$WORK/guard-cfg"
mkdir -p "$GUARD_HOME/$CID"
cp "$OWNER_HOME/$CID/keystore.json" "$GUARD_HOME/$CID/keystore.json"
if CORD_GIT_HOME="$GUARD_HOME" "$CORD_BIN" revoke "$READER2_PUB" --dir "$OWNER4" >"$WORK/guard-revoke.log" 2>&1; then
  fail "pre-mint guard: rival revoke should have been refused"
else
  if grep -qi "already exist" "$WORK/guard-revoke.log"; then
    pass "pre-mint guard refuses a rival rotation while rekeys are live"
  else
    fail "pre-mint guard refused for wrong reason"; cat "$WORK/guard-revoke.log"
  fi
fi
# 30c: GitLab !12 — the retained reader folds DURING the publish window
# (state+collab visible, write missing): the fold MUST refuse to apply the
# partial epoch and MUST NOT advance (epoch stays 2).
if CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" fold "$CID" --nsec "$READER_NSEC" >"$WORK/reader-fold-partial.log" 2>&1; then
  fail "fold applied a partial epoch (state+collab only)"
else
  EPOCH_NOW="$(CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" status "$CID" 2>/dev/null | sed -n 's/^epoch: *//p' | tr -d ' ')"
  if grep -qi "incomplete" "$WORK/reader-fold-partial.log" && [ "$EPOCH_NOW" = "2" ]; then
    pass "fold refuses a partial epoch (nothing applied, epoch still 2)"
  else
    fail "partial-epoch fold wrong result (epoch=$EPOCH_NOW)"; cat "$WORK/reader-fold-partial.log"
  fi
fi
# 30d-pre: the squatter also claims the write-scope address (the state squat
# is already live; collab was added on-demand by the aborted revoke's minimal
# widen fallback — all three addresses must be admittable for the flood).
CORD_GIT_ALLOW_DEBUG=1 CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" debug-squat-rekey "$CID" --scope write >>"$WORK/squat2.log" 2>&1
# 30d: GitLab !13 — while the widen is still live, a READ-ONLY member floods
# all three rekey addresses with 600 junk wraps sharing ONE crafted created_at
# second (the worst case for inclusive-`until` pagination). The genuine write
# rekey (published by the resume below) is past-tweaked and lands BEHIND the
# junk in any newest-first window. Tenant-forgeries are also storable now
# that the window is open — folds must skip both.
FLOOD_OUT="$(CORD_GIT_ALLOW_DEBUG=1 CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" debug-flood-rekey "$CID" --count 600 --same-second 2>&1)"
echo "$FLOOD_OUT" | sed 's/^/  flood: /'
if printf '%s\n' "$FLOOD_OUT" | grep -c 'admitted=600/600' | grep -q 3; then
  pass "flood window: 600 same-second junk wraps per scope admitted mid-rotation"
else
  fail "flood not fully admitted during the widen window"; echo "$FLOOD_OUT"
fi
FORGE_IN_WINDOW="$(CORD_GIT_ALLOW_DEBUG=1 CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" debug-forge-rekey "$CID" --victim "$WRITER_PUB" 2>&1)"
if printf '%s' "$FORGE_IN_WINDOW" | grep -q 'forged_state_rekey_admitted=true' \
   && printf '%s' "$FORGE_IN_WINDOW" | grep -q 'forged_write_rekey_admitted=true'; then
  pass "in-window forgeries admitted (fold must skip them, not the server)"
else
  fail "in-window forgeries were not admitted — the 30f skip-leg is vacuous"; echo "$FORGE_IN_WINDOW"
fi
# 30e: GitLab !14 — resume the interrupted rotation: must republish the
# PERSISTED artifacts byte-identically (no second genuine rekey set minted).
cp "$OWNER_HOME/$CID/pending-epoch.json" "$WORK/pending-backup-epoch3.json"
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" revoke "$READER2_PUB" --dir "$OWNER4" >"$WORK/revoke-resume.log" 2>&1 \
   && grep -qi "resuming the interrupted rotation" "$WORK/revoke-resume.log" \
   && [ ! -f "$OWNER_HOME/$CID/pending-epoch.json" ]; then
  pass "resume completes the interrupted rotation byte-identically (pending file consumed)"
else
  fail "resume revoke"; cat "$WORK/revoke-resume.log"
fi
# 30f: the retained reader folds THROUGH the flood: until-pagination finds the
# genuine (past-tweaked) write rekey behind 600 junk wraps, exactly one
# genuine set exists (the loud-fork rule stays silent), and the non-tenant
# forgeries planted in the window are skipped.
if CORD_GIT_HOME="$READER_HOME" "$CORD_BIN" fold "$CID" --nsec "$READER_NSEC" >"$WORK/reader-fold-flood.log" 2>&1 \
   && grep -q "folded 1 rotation" "$WORK/reader-fold-flood.log"; then
  pass "fold survives 600+ flooded junk wraps (pagination) and skips in-window forgeries"
else
  fail "reader fold through flood"; cat "$WORK/reader-fold-flood.log"
fi
# reader2 was revoked in this epoch: exclusion is reported (fold from epoch 0
# walks demote + revoke + this revoke and stops at the exclusion).
if CORD_GIT_HOME="$READER2_HOME" "$CORD_BIN" fold "$CID" --nsec "$READER2_NSEC" >"$WORK/reader2-fold.log" 2>&1; then
  fail "revoked reader2 fold should have reported exclusion"
else
  if grep -qi "excluded" "$WORK/reader2-fold.log"; then
    pass "revoked reader2 fold reports exclusion"
  else
    fail "reader2 fold failed for wrong reason"; cat "$WORK/reader2-fold.log"
  fi
fi
# 30g: GitLab !14 — the OWNER recovers via fold after local-state loss:
# restore the pre-rotation keystore (epoch 2) and fold with the hosting key
# (the owner slots minted by this fix carry the new secrets).
cp "$WORK/owner-keystore-pre-epoch3.json" "$OWNER_HOME/$CID/keystore.json"
HOSTING_NSEC="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['hosting_nsec'])" "$OWNER_HOME/$CID/keystore.json")"
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" fold "$CID" --nsec "$HOSTING_NSEC" >"$WORK/owner-fold.log" 2>&1 \
   && grep -q "folded 1 rotation" "$WORK/owner-fold.log"; then
  pass "owner recovered the rotation via fold (owner slots in rekeys)"
else
  fail "owner fold recovery"; cat "$WORK/owner-fold.log"
fi
# ...and the recovered owner can push with the fold-recovered secrets.
sleep 1.1
echo "owner recovered" >> "$OWNER4/README.md"
git -C "$OWNER4" commit -aq -m "owner recovered" 2>/dev/null
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" push --dir "$OWNER4" --force >"$WORK/owner-push6.log" 2>&1; then
  pass "owner pushes with fold-recovered secrets"
else
  fail "owner push after fold recovery"; cat "$WORK/owner-push6.log"
fi

# 30h: rival-resume refusal — a stale pending file must never regress a
# LATER landed rotation. Complete another rotation (epoch 4), then present
# the epoch-2 keystore + the epoch-3 pending backup (the two-device case):
# the resume must REFUSE, not mint a rival rekey set / regress the registry.
OWNER5="$WORK/owner-epoch4"
CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" clone "$CID" "$OWNER5" >/dev/null 2>&1
sleep 1.1
if CORD_GIT_HOME="$OWNER_HOME" "$CORD_BIN" revoke "$READER_PUB" --dir "$OWNER5" >"$WORK/revoke-reader.log" 2>&1; then
  pass "epoch-4 rotation (revoke reader) completes"
else
  fail "epoch-4 revoke"; cat "$WORK/revoke-reader.log"
fi
RIVAL_HOME="$WORK/rival-cfg"
mkdir -p "$RIVAL_HOME/$CID"
cp "$WORK/owner-keystore-pre-epoch3.json" "$RIVAL_HOME/$CID/keystore.json"
cp "$WORK/pending-backup-epoch3.json" "$RIVAL_HOME/$CID/pending-epoch.json"
if CORD_GIT_HOME="$RIVAL_HOME" "$CORD_BIN" revoke "$READER2_PUB" --dir "$OWNER5" >"$WORK/rival-revoke.log" 2>&1; then
  fail "rival resume should have been refused (a later rotation already landed)"
else
  # Loud either way: a revoke-rival also breaks manifest decryption (the
  # stale keystore's state key predates the landed rotation); a demote-rival
  # hits the rival-resume guard itself.
  if grep -qiE "rival rotation landed|aead|decrypt" "$WORK/rival-revoke.log"; then
    pass "stale pending resume refused loudly (rival rotation landed / undecryptable manifest)"
  else
    fail "rival resume failed for wrong reason"; cat "$WORK/rival-revoke.log"
  fi
fi

# --- 31: multi-relay partial-publish resume + staged epoch fork -------------
# A rotation interrupted with the widen live on node A ONLY must, on resume,
# republish widen+rekeys+narrow to the lagging node B — never skip
# republication because "it's live somewhere" (silent revocation bypass on
# the laggard). Also: two genuine tenant-signed rekeys at one address must
# fail the fold loudly, never first-parse-wins.
PORT2="${PORT2:-7363}"
RELAY2="ws://127.0.0.1:${PORT2}"
SERVER2="http://127.0.0.1:${PORT2}"
SRV2_DATA="$WORK/srvdata2"
mkdir -p "$SRV2_DATA"
(cd "$SRV2_DATA" && exec env NGIT_DOMAIN="127.0.0.1:${PORT2}" NGIT_BIND_ADDRESS="127.0.0.1:${PORT2}" \
  NGIT_DATABASE_BACKEND=memory NGIT_GRASP_P_REPOS_ENABLE=true \
  NGIT_GRASP_P_REGISTRATION_MODE=open NGIT_GRASP_P_WRITE_RATE_CAPACITY=0 \
  NGIT_GRASP_P_REGISTRATION_REPLACE_CAPACITY=0 \
  NGIT_RELAY_DATA_PATH="$SRV2_DATA/relay" NGIT_GIT_DATA_PATH="$SRV2_DATA/git" \
  "$SERVER_BIN" >"$WORK/server2.log" 2>&1) &
SRV2_PID=$!
for _ in $(seq 1 50); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$SERVER2/" 2>/dev/null || true)"
  [ "$code" = "200" ] && break
  sleep 0.2
done
if [ "$(curl -s -o /dev/null -w '%{http_code}' "$SERVER2/")" != "200" ]; then
  echo "server2 did not start; log:"; cat "$WORK/server2.log"; exit 2
fi
echo "server2 up on $PORT2 (pid $SRV2_PID)"

# Fresh community; the keystore is then pointed at BOTH nodes (so rotation
# artifacts must land on both).
M_HOME="$WORK/multi-cfg"
M_REPO="$WORK/multi-repo"
mkdir -p "$M_REPO"
git -C "$M_REPO" init --quiet
git -C "$M_REPO" config user.email e2e@example.com
git -C "$M_REPO" config user.name e2e
git -C "$M_REPO" checkout -q -b main
echo "multi-relay repo" > "$M_REPO/README.md"
git -C "$M_REPO" add -A
git -C "$M_REPO" commit -q -m "initial"
CREATE2_OUT="$(CORD_GIT_HOME="$M_HOME" "$CORD_BIN" create demo2 --relay "$RELAY" --server "$SERVER" --dir "$M_REPO" 2>&1)"
CID2="$(printf '%s\n' "$CREATE2_OUT" | sed -n 's/.*community_id: //p' | tr -d ' ')"
if [ -z "$CID2" ]; then fail "create (multi)"; echo "$CREATE2_OUT"; exit 1; fi
CORD_GIT_HOME="$M_HOME" "$CORD_BIN" push --dir "$M_REPO" >"$WORK/mpush.log" 2>&1 \
  && pass "multi-relay community created + pushed" || { fail "multi create/push"; cat "$WORK/mpush.log"; }
python3 - "$M_HOME/$CID2/keystore.json" "$RELAY2" "$SERVER2" <<'PY'
import json, sys
p = sys.argv[1]
ks = json.load(open(p))
ks["relays"] = ks["relays"] + [sys.argv[2]]
ks["servers"] = ks["servers"] + [sys.argv[3]]
json.dump(ks, open(p, "w"))
PY
# A writer member to demote.
V_KEYS="$("$CORD_BIN" keygen)"
V_NSEC="$(printf '%s\n' "$V_KEYS" | sed -n 's/^nsec: //p')"
V_PUB="$(printf '%s\n' "$V_KEYS" | sed -n 's/^pubkey: //p')"
CORD_GIT_HOME="$M_HOME" "$CORD_BIN" invite "$V_PUB" --write --via "$INBOX" --dir "$M_REPO" >"$WORK/invite-v.log" 2>&1
V_HOME="$WORK/multi-v-cfg"
V_REPO="$WORK/multi-v-repo"
if CORD_GIT_HOME="$V_HOME" "$CORD_BIN" join --nsec "$V_NSEC" --relay "$INBOX" >"$WORK/join-v.log" 2>&1 \
   && CORD_GIT_HOME="$V_HOME" "$CORD_BIN" clone "$CID2" "$V_REPO" >"$WORK/clone-v.log" 2>&1; then
  pass "multi: writer invited + joined + cloned"
else
  fail "multi writer setup"; cat "$WORK/invite-v.log" "$WORK/join-v.log" "$WORK/clone-v.log" 2>/dev/null
fi
# Back up the epoch-0 owner keystore (for the fold assertions below).
cp "$M_HOME/$CID2/keystore.json" "$WORK/multi-ks-epoch0.json"
M_HOSTING_NSEC="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['hosting_nsec'])" "$WORK/multi-ks-epoch0.json")"
M_TENANT_PUB="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['tenant_pub'])" "$WORK/multi-ks-epoch0.json")"

# Kill node B, then demote V: the widen lands on A only; the command fails —
# but the pending epoch MUST already be persisted (persist-before-publish).
kill "$SRV2_PID" 2>/dev/null; wait "$SRV2_PID" 2>/dev/null; SRV2_PID=""
if CORD_GIT_HOME="$M_HOME" "$CORD_BIN" demote "$V_PUB" --dir "$M_REPO" >"$WORK/demote-bdown.log" 2>&1; then
  fail "demote should have failed with node B down"
else
  if [ -f "$M_HOME/$CID2/pending-epoch.json" ]; then
    pass "node-B-down demote failed with the pending epoch already persisted (before any publish)"
  else
    fail "no pending epoch after the node-B-down failure"; cat "$WORK/demote-bdown.log"
  fi
fi
# While the widen is live on A only, stage the !14 fork: a SECOND genuine
# (tenant-signed) write-scope rekey at the same address, poisoned slot.
FORK_OUT="$(CORD_GIT_ALLOW_DEBUG=1 CORD_GIT_HOME="$M_HOME" "$CORD_BIN" debug-fork-rekey "$CID2" --victim "$M_TENANT_PUB" 2>&1)"
if printf '%s' "$FORK_OUT" | grep -q 'forked_write_rekey_admitted=true'; then
  pass "staged fork: second genuine rekey admitted on A (widen window)"
else
  fail "staged fork not admitted"; echo "$FORK_OUT"
fi
# Restart B (empty: memory backend) and resume — must republish EVERYTHING to B.
(cd "$SRV2_DATA" && exec env NGIT_DOMAIN="127.0.0.1:${PORT2}" NGIT_BIND_ADDRESS="127.0.0.1:${PORT2}" \
  NGIT_DATABASE_BACKEND=memory NGIT_GRASP_P_REPOS_ENABLE=true \
  NGIT_GRASP_P_REGISTRATION_MODE=open NGIT_GRASP_P_WRITE_RATE_CAPACITY=0 \
  NGIT_GRASP_P_REGISTRATION_REPLACE_CAPACITY=0 \
  NGIT_RELAY_DATA_PATH="$SRV2_DATA/relay" NGIT_GIT_DATA_PATH="$SRV2_DATA/git" \
  "$SERVER_BIN" >>"$WORK/server2.log" 2>&1) &
SRV2_PID=$!
for _ in $(seq 1 50); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$SERVER2/" 2>/dev/null || true)"
  [ "$code" = "200" ] && break
  sleep 0.2
done
if CORD_GIT_HOME="$M_HOME" "$CORD_BIN" demote "$V_PUB" --dir "$M_REPO" >"$WORK/demote-resume.log" 2>&1 \
   && grep -qi "resuming the interrupted rotation" "$WORK/demote-resume.log" \
   && [ ! -f "$M_HOME/$CID2/pending-epoch.json" ]; then
  pass "resume republishes widen+rekey+narrow to the lagging node B"
else
  fail "resume with lagging node B"; cat "$WORK/demote-resume.log"
fi
# Owner fold on A (epoch-0 keystore): the real rekey + the staged poison are
# BOTH genuine → the fold must fail LOUDLY, never first-parse-wins.
cp "$WORK/multi-ks-epoch0.json" "$M_HOME/$CID2/keystore.json"
if CORD_GIT_HOME="$M_HOME" "$CORD_BIN" fold "$CID2" --nsec "$M_HOSTING_NSEC" >"$WORK/mfold-a.log" 2>&1; then
  fail "owner fold on A should have hit the staged fork"
else
  if grep -qi "fork" "$WORK/mfold-a.log"; then
    pass "two genuine rekeys at one address = loud fork, no silent pick"
  else
    fail "owner fold on A failed for the wrong reason"; cat "$WORK/mfold-a.log"
  fi
fi
# Owner fold on B (B-only keystore): B has ONLY the genuine set (the poison
# went to A while B was down) → the fold succeeds, proving the resume
# republished the rekeys to the lagging node.
MB_HOME="$WORK/multi-b-cfg"
mkdir -p "$MB_HOME/$CID2"
python3 - "$WORK/multi-ks-epoch0.json" "$MB_HOME/$CID2/keystore.json" "$RELAY2" <<'PY'
import json, sys
ks = json.load(open(sys.argv[1]))
ks["relays"] = [sys.argv[3]]
json.dump(ks, open(sys.argv[2], "w"))
PY
if CORD_GIT_HOME="$MB_HOME" "$CORD_BIN" fold "$CID2" --nsec "$M_HOSTING_NSEC" >"$WORK/mfold-b.log" 2>&1 \
   && grep -q "folded 1 rotation" "$WORK/mfold-b.log"; then
  pass "owner fold on B succeeds (resume republished rekeys to the laggard)"
else
  fail "owner fold on B"; cat "$WORK/mfold-b.log"
fi
# The demoted member's OLD write key was freed on B by the narrow: a push
# against B must be rejected (revocation landed everywhere, not just on A).
VB_HOME="$WORK/multi-vb-cfg"
mkdir -p "$VB_HOME/$CID2"
python3 - "$V_HOME/$CID2/keystore.json" "$VB_HOME/$CID2/keystore.json" "$RELAY2" "$SERVER2" <<'PY'
import json, sys
ks = json.load(open(sys.argv[1]))
ks["relays"] = [sys.argv[3]]
ks["servers"] = [sys.argv[4]]
json.dump(ks, open(sys.argv[2], "w"))
PY
echo "demoted push attempt" >> "$V_REPO/README.md"
git -C "$V_REPO" config user.email v@example.com
git -C "$V_REPO" config user.name v
git -C "$V_REPO" commit -aq -m "demoted edit" 2>/dev/null
if CORD_GIT_HOME="$VB_HOME" "$CORD_BIN" push --dir "$V_REPO" --force >"$WORK/vpush-b.log" 2>&1; then
  fail "demoted member push should have been rejected on node B"
else
  if grep -qiE 'registered write key|rejected|restricted|forbidden' "$WORK/vpush-b.log"; then
    pass "demoted member push rejected on node B (narrow landed everywhere)"
  else
    fail "demoted push on B failed for the wrong reason"; cat "$WORK/vpush-b.log"
  fi
fi

echo "==============================="
if [ "$FAILED" -eq 0 ]; then
  echo "E2E: ALL GREEN"
else
  echo "E2E: FAILURES ABOVE"
fi
exit "$FAILED"
