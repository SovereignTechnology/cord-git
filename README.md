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

## History across revocations (GitLab #21)

Removing a collaborator from a private GitHub repo destroys nothing for the
remaining members: issues, PRs and comments stay readable, and a newly added
collaborator sees the whole back-history. cord-git matches that: a refounding
(revoke) rolls the `#collab` key, and the outgoing key is retired into a
per-keystore prior-key ring (`prior_collab_keys`), so retained members keep
reading pre-revocation `#collab` and guestbook history. Collab rekey slots and
invite bundles hand the ring over, so members who joined later — including
after the revoke — see the back-history too.

- **Retired keys are read-only**: each ring entry records when its key was
  retired, and wraps whose *inner* rumor postdates that retirement are
  rejected, with the epoch tag bound to the matched ring entry. A revoked
  member cannot use their old key to inject new issues, pin thread statuses,
  or forge guestbook joins — revocation removes posting rights exactly like
  GitHub does. (Backdated injection under an old key is indistinguishable
  from real pre-revocation activity — irreducible with symmetric keys — and
  can never out-sort post-revocation content.)
- **Policy knob**: `retain_collab_history` in the keystore, default `true`
  (GitHub parity). Set `false` to make every revoke truncate history for this
  keystore as a *deliberate policy* — the tradeoff is real: the ring means a
  device compromise exposes every retained epoch, while with the knob off a
  compromise exposes only the current one. Retention is capped at the last
  256 retired epochs (bounds rekey-slot/invite payloads against the NIP-44
  ceiling).
- **The one deliberate divergence from GitHub**: revocation is not
  retroactive. GitHub can cut a removed collaborator off from old content
  because GitHub holds the plaintext; a content-blind relay never does. A
  revoked member keeps every byte they already pulled, forever, and the old
  ciphertext stays on the relay. Rolling the key therefore buys no forward
  secrecy over *old* content — what it guarantees (and what the ring
  preserves) is that a revoked member can never read content created *after*
  their revocation: they receive no refounding slot, so key N+1 never reaches
  them.
