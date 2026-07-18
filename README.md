# cord-git — CORD-git client for GRASP-P private repos

Client for GitHub-style **private** git repositories hosted on public
Nostr/GRASP nodes running the GRASP-P server extension, where the operator is
untrusted (content-blind): packs and manifests are AEAD-encrypted client-side,
membership/keys/invites are tenant-side.

- `cord-core` — library: crypto, keystore, manifest, events, relay/blob/git.
- `cord-git` — CLI: `create`, `push`, `clone`, `status`, `doctor`.

## Quick start (against a local GRASP-P node)

```
cord-git create demo --relay ws://NODE:PORT --server http://NODE:PORT   # in a git repo
cord-git push                                                            # publish
cord-git clone <community_id> ./somewhere                                # elsewhere
```

Secrets live under `CORD_GIT_HOME` (default `~/.config/cord-git`), 0600.

## Status

Phase 3 (see `../ref/ngit-grasp/docs/grasp-p/phase3-*.md`): create/push/clone +
client-side CAS, proven end-to-end against a live server (`scripts/e2e.sh`).
Invite/join/revoke and the `git-remote-cord` helper are Phase 4. The
membership/crypto layer is CORD-git-native; Concord byte-conformance is deferred.
