# cord-git: client for GRASP-P private repositories

Private git repositories on a public Nostr/GRASP server whose operator is not
trusted. This client encrypts packs and manifests before upload and manages
keys, membership and invites itself; the server only ever stores ciphertext
and opaque public keys.

For how the whole system fits together, read the server repo's
`docs/grasp-p/OVERVIEW.md`. The full convention is `docs/grasp-p/CORD-git-v0-spec.md`.

**Status: working prototype, not yet a product.** See [Known gaps](#known-gaps).

## Crates

| Crate | What it is |
|---|---|
| `cord-core` | Library: crypto, keystore, manifest, events, relay, blob and git plumbing |
| `cord-git` | The CLI |
| `inbox-relay` | A minimal relay used by the end-to-end tests |

## Quick start

Against a GRASP-P node (whitelist-mode nodes need a hosting key the operator has
admitted, supplied in `CORD_GIT_HOSTING_NSEC`):

```
cord-git create demo --relay wss://NODE --server https://NODE   # in a git repo
cord-git push                                                    # encrypt and publish
cord-git clone <community_id> ./somewhere                        # with a keystore for it
```

Adding a collaborator:

```
cord-git invite <npub> --write --via wss://THEIR-INBOX-RELAY     # owner
cord-git join --relay wss://THEIR-INBOX-RELAY                    # invitee
cord-git clone <community_id> ./repo                             # invitee
```

Removing one:

```
cord-git revoke <npub>            # owner: rotate secrets, lock them out
cord-git fold <community_id>      # every remaining member: pick up the new keys
```

## Commands

| Command | What it does |
|---|---|
| `create NAME --relay --server` | Register a new private repo and link the directory |
| `push [--force]` | Pack, encrypt, upload and publish the current state |
| `clone COMMUNITY_ID DIR` | Clone a repo you hold a keystore for |
| `invite NPUB [--write] --via RELAY` | Deliver an invite to the invitee's own inbox relay |
| `join --relay RELAY` or `--file F` | Consume an invite and publish a guestbook entry |
| `revoke NPUB` | Ban a member and refound the repo's secrets |
| `demote NPUB` | Writer to reader, without a full refounding |
| `promote NPUB --via RELAY` / `promote-accept` | Grant and accept the write role |
| `rotate` | Roll the write secret and state key |
| `fold COMMUNITY_ID` | Apply pending rotations to your keystore |
| `issue new\|list\|show\|comment\|close` | Encrypted issues |
| `pr new\|list\|show\|status` | Encrypted patch series |
| `roster`, `status`, `doctor` | Inspect members, the keystore and connectivity |
| `keygen` | Generate a Nostr identity |

Invites and promotions are never sent to a git node; the client refuses.

## Keys and storage

- Keystore: `$CORD_GIT_HOME` or `~/.config/cord-git/<community_id>/keystore.json`,
  mode 0600 in a 0700 directory.
- Your member key is read from `CORD_GIT_NSEC` (or `--nsec`). Prefer the
  environment variable: an argument is visible to other processes.
- The hosting key comes from `CORD_GIT_HOSTING_NSEC`, otherwise a fresh one is generated.

## Tests

`cargo test` runs the `cord-core` unit tests. `scripts/e2e.sh` runs the full
scenario suite against a GRASP-P server binary (`SERVER_BIN`, `CORD_BIN`,
`INBOX_BIN`; ports 7361-7363).

## Known gaps

Tracked as issues; none of these are fixed yet.

- No `fetch` or `pull` into an existing clone, and no `git` remote helper.
- Every push uploads the full history as a single pack.
- The keystore is plaintext on disk; there is no remote-signer (NIP-46) support.
- A hostile operator can serve an older, validly signed state.
- Invite bundles do not prove who sent them.
- A failed rotation can leave a revoked key registered until it is retried.
- Only `refs/heads` are synced (no tags).

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
