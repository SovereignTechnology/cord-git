//! High-level create / push / clone orchestration tying crypto + keystore +
//! events + relay + blob + git together. See design §3, §4, §7.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::collab::{self, CollabPublish, Status, Thread};
use crate::crypto;
use crate::events::{self, BlobOp};
use crate::invite::{self, InviteBundle, JoinInfo};
use crate::keystore::{BanEntry, Keystore, Role, RosterEntry};
use crate::manifest::{Manifest, PackEntry};
use crate::rekey::{self, Scope};
use crate::{blob, git, relay};

/// The `.cord-git` pointer file written into a working repo linking it to a
/// community.
const POINTER_FILE: &str = ".cord-git";

/// Maximum clock-skew tolerance for accepting an event's `created_at` as
/// "not future-dated". Anything newer is rejected: a future-dated 30641 would
/// otherwise win the latest-edition sort indefinitely (pin/rollback attack).
const FUTURE_SLACK_SECS: u64 = 900;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Extract the registered write-key pubkeys (first value of each `w` tag).
fn parse_w_keys(registration: &nostr::Event) -> Vec<String> {
    parse_tag_keys(registration, "w")
}

/// Extract the registered aux (stream) pubkeys (`aux` tags).
fn parse_aux_keys(registration: &nostr::Event) -> Vec<String> {
    parse_tag_keys(registration, "aux")
}

fn parse_tag_keys(registration: &nostr::Event, tag: &str) -> Vec<String> {
    registration
        .tags
        .iter()
        .filter_map(|t| {
            let v = t.clone().to_vec();
            if v.len() >= 2 && v[0] == tag {
                Some(v[1].clone())
            } else {
                None
            }
        })
        .collect()
}

/// The newest signature-valid, tenant-authored, not-future-dated 30640 from
/// raw candidates.
fn newest_valid_registration(
    mut regs: Vec<nostr::Event>,
    tenant_hex: &str,
    now: u64,
) -> Option<nostr::Event> {
    regs.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.to_hex().cmp(&b.id.to_hex()))
    });
    regs.into_iter()
        .find(|reg| registration_is_valid(reg, tenant_hex, now))
}

/// Is this 30640 the authentic live registration for `tenant_hex`?
/// Signature-valid, authored by the tenant, not future-dated.
fn registration_is_valid(reg: &nostr::Event, tenant_hex: &str, now: u64) -> bool {
    reg.pubkey.to_hex() == tenant_hex
        && reg.verify().is_ok()
        && reg.created_at.as_secs() <= now + FUTURE_SLACK_SECS
}

/// Is this 30641 trustworthy? Signature-valid, authored by a CURRENT registered
/// write key, not future-dated. This is what makes revocation real: after a
/// rotation the old write key is out of the w-set, so its events — including
/// any future-dated ones planted before revocation — are never selected.
fn state_root_is_valid(ev: &nostr::Event, w_keys: &[String], now: u64) -> bool {
    ev.verify().is_ok()
        && w_keys.iter().any(|k| *k == ev.pubkey.to_hex())
        && ev.created_at.as_secs() <= now + FUTURE_SLACK_SECS
}

/// Select the newest valid 30641 from raw candidates (created_at desc,
/// tie → lowest id — mirroring addressable-replacement semantics).
pub fn select_valid_state_root(
    mut candidates: Vec<nostr::Event>,
    w_keys: &[String],
    now: u64,
) -> Option<nostr::Event> {
    candidates.retain(|ev| state_root_is_valid(ev, w_keys, now));
    candidates.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.to_hex().cmp(&b.id.to_hex()))
    });
    candidates.into_iter().next()
}

/// The current registered write-key set for this keystore's alias, from the
/// signature-verified live registration.
fn live_w_keys(ks: &Keystore) -> Result<Vec<String>> {
    let relay_url = ks.relays.first().context("no relay configured")?;
    let tenant_hex = ks.tenant_hex()?;
    let regs = relay::registration_candidates(relay_url, &ks.alias)?;
    newest_valid_registration(regs, &tenant_hex, now_secs())
        .map(|reg| parse_w_keys(&reg))
        .ok_or_else(|| anyhow!("no valid live registration (30640) found for this alias"))
}

/// Fetch the newest 30641 that is signature-valid, authored by a current
/// registered write key, and not future-dated. Every read path (push CAS,
/// clone, rotate, doctor) MUST use this — never raw relay results.
pub fn latest_valid_state_root(ks: &Keystore) -> Result<Option<nostr::Event>> {
    let w_keys = live_w_keys(ks)?;
    let relay_url = ks.relays.first().context("no relay configured")?;
    let candidates = relay::state_root_candidates(relay_url, &ks.alias)?;
    Ok(select_valid_state_root(candidates, &w_keys, now_secs()))
}

/// Result of a create.
pub struct Created {
    pub community_id: String,
    pub alias: String,
    pub url: String,
}

/// `cord-git create` — generate all secrets, register (30640), persist the
/// keystore, and drop a `.cord-git` pointer in `repo_dir`.
pub fn create(
    repo_dir: &Path,
    name: &str,
    node_relay: &str,
    node_server: &str,
) -> Result<Created> {
    let hosting = nostr::Keys::generate();
    let salt = crypto::random_32();
    let community_id = crypto::community_id(&hosting.public_key(), &salt);
    if Keystore::exists(&community_id) {
        bail!("community {community_id} already exists locally");
    }
    let state_key = crypto::random_32();
    let collab_key = crypto::random_32();
    let community_root = crypto::random_32();
    let write_secret = crypto::random_32();
    let alias = hex::encode(crypto::random_32())[..32].to_string();
    let epoch = 0u32;
    let write_keys = crypto::derive_write_keys(&write_secret, epoch)?;

    let ks = Keystore {
        community_id: community_id.clone(),
        repo_name: name.to_string(),
        hosting_nsec: Some(hosting.secret_key().to_secret_hex()),
        tenant_pub: Some(hosting.public_key().to_hex()),
        owner_salt: hex::encode(salt),
        state_key: hex::encode(state_key),
        collab_key: hex::encode(collab_key),
        community_root: Some(hex::encode(community_root)),
        write_secret: Some(hex::encode(write_secret)),
        epoch,
        alias: alias.clone(),
        relays: vec![node_relay.to_string()],
        servers: vec![node_server.to_string()],
        role: Role::Write,
        manifest_prev: None,
        roster: Vec::new(),
        banned: Vec::new(),
    };

    // Register with the write key AND the derived guestbook stream key in the
    // aux set (aux admits 1059 guestbook wraps but can never write blobs or
    // state roots — the server enforces the split).
    let guestbook = ks.guestbook_keys()?;
    let reg = events::build_registration(
        &hosting,
        &write_keys,
        &[&guestbook],
        &alias,
        &ks.relays,
        &ks.servers,
    )?;
    let out = relay::publish(node_relay, &reg)?;
    if !out.accepted {
        bail!("registration rejected by node: {}", out.message);
    }
    ks.save()?;
    write_pointer(repo_dir, &community_id)?;

    // Genesis guestbook Join: the owner (as the hosting pseudonym) is the
    // first member. Outer wrap = derived guestbook key, per the normative rule.
    publish_join(&hosting, &ks)
        .context("registration succeeded but the genesis guestbook join failed")?;

    Ok(Created {
        url: format!("cord://{community_id}"),
        community_id,
        alias,
    })
}

/// Build, publish, and confirm a guestbook Join for `member`; retains the raw
/// rumor JSON bytes under the community dir (flip-public needs byte-exact
/// republish). Returns the outer 1059 event id.
fn publish_join(member: &nostr::Keys, ks: &Keystore) -> Result<String> {
    let relay_url = ks.relays.first().context("no relay configured")?;
    let (outer, raw) = invite::build_join(member, ks)?;

    // Retain the raw signed rumor bytes (0600) BEFORE publishing.
    let dir = Keystore::community_dir(&ks.community_id)?.join("guestbook");
    std::fs::create_dir_all(&dir)?;
    crate::keystore::write_0600(&dir.join(format!("{}.json", outer.id.to_hex())), &raw)?;

    let out = relay::publish(relay_url, &outer)?;
    if !out.accepted {
        bail!("guestbook join rejected by node: {}", out.message);
    }
    // OK=true is not a commit marker — read back and confirm our wrap is
    // served. Id-pinned: a flooded stream address must not hide it (!13).
    let stored = relay::event_by_id(relay_url, &outer.id.to_hex())?;
    let ours = stored
        .iter()
        .find(|e| e.id == outer.id && e.verify().is_ok());
    if ours.is_none() {
        bail!("guestbook join was accepted but is not served back by the node");
    }
    Ok(outer.id.to_hex())
}

/// Normalize a relay URL for comparison (scheme+host+port, trailing slash and
/// case-insensitive host).
fn normalize_relay_url(u: &str) -> String {
    u.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// `cord-git invite` — grant `role` to `invitee` in the roster and deliver the
/// 3313 bundle to the invitee's OWN inbox relay. NORMATIVE: never to the git
/// nodes (refused here). Returns the wrap event id.
pub fn invite(
    repo_dir: &Path,
    invitee: &str,
    write: bool,
    via_relay: &str,
    out_file: Option<&Path>,
) -> Result<String> {
    let community_id = read_pointer(repo_dir)?;
    let mut ks = Keystore::load(&community_id)?;
    if !ks.is_owner() {
        bail!("only the repo owner (hosting-key holder) can invite");
    }
    if load_pending(&community_id)?.is_some() {
        bail!(
            "an interrupted rotation is still pending — complete it first \
             (rerun the revoke/demote command); a grant now would be rolled \
             back when the pending rotation adopts its roster snapshot"
        );
    }
    let role = if write { Role::Write } else { Role::Read };

    // NORMATIVE leak-management rule: the invite must ride the invitee's own
    // inbox relay, never a git node (the node refuses them anyway:
    // NGIT_PRIVATE_ACCEPT_DIRECT_INVITES=false).
    let via_norm = normalize_relay_url(via_relay);
    if ks.relays.iter().any(|r| normalize_relay_url(r) == via_norm) {
        bail!(
            "refusing to deliver an invite to a git node ({via_relay}) — \
             use the invitee's own inbox relay"
        );
    }

    let invitee_pk = nostr::PublicKey::parse(invitee)
        .map_err(|e| anyhow!("invalid invitee npub: {e}"))?;
    let invitee_hex = invitee_pk.to_hex();

    // Record the Grant in the roster (upsert by npub), then snapshot it into
    // the bundle.
    ks.roster.retain(|e| e.npub != invitee_hex);
    ks.roster.push(RosterEntry {
        npub: invitee_hex.clone(),
        role,
        granted_at: now_secs(),
    });
    ks.save()?;

    let bundle = InviteBundle::from_keystore(&ks, role)?;
    let wrap = invite::wrap_invite(&bundle, &invitee_pk)?;

    let out = relay::publish(via_relay, &wrap)?;
    if !out.accepted {
        bail!("inbox relay rejected the invite: {}", out.message);
    }
    // Confirm the inbox relay serves it back (id-pinned — flood-proof).
    let stored = relay::event_by_id(via_relay, &wrap.id.to_hex())?;
    if !stored.iter().any(|e| e.id == wrap.id) {
        bail!("invite was accepted but is not served back by the inbox relay");
    }

    if let Some(path) = out_file {
        crate::keystore::write_0600(path, wrap.as_json().as_bytes())?;
    }
    Ok(wrap.id.to_hex())
}

/// Where a joiner gets the invite wrap from.
pub enum InviteSource {
    /// Fetch from the invitee's inbox relay.
    Relay(String),
    /// Offline handoff: a file containing the wrap event JSON.
    File(std::path::PathBuf),
    /// Offline handoff via stdin.
    Stdin,
}

/// `cord-git join` — consume an invite addressed to `member_keys`, import the
/// member keystore, and publish the guestbook Join. The Join goes out only
/// AFTER the bundle is held AND the live registration verifies against the
/// bundled tenant pubkey. Returns the community id.
pub fn join(member_keys: &nostr::Keys, source: InviteSource) -> Result<String> {
    let bundle = match source {
        InviteSource::Relay(url) => {
            let me = member_keys.public_key().to_hex();
            let wraps = relay::giftwraps_for(&url, &me)?;
            let mut last_err: Option<anyhow::Error> = None;
            let mut found = None;
            for wrap in &wraps {
                // unwrap_invite verifies the wrap signature first.
                match invite::unwrap_invite(member_keys, wrap) {
                    Ok(b) => {
                        found = Some(b);
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            found.ok_or_else(|| match last_err {
                Some(e) => anyhow!("no usable invite on {url} for this key (last error: {e})"),
                None => anyhow!("no invite wraps addressed to this key on {url}"),
            })?
        }
        InviteSource::File(path) => {
            let json = std::fs::read_to_string(&path)
                .with_context(|| format!("cannot read invite file {path:?}"))?;
            let wrap = nostr::Event::from_json(&json)
                .map_err(|e| anyhow!("invite file is not an event: {e}"))?;
            invite::unwrap_invite(member_keys, &wrap)?
        }
        InviteSource::Stdin => {
            let mut json = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut json)?;
            let wrap = nostr::Event::from_json(json.trim())
                .map_err(|e| anyhow!("stdin is not an invite event: {e}"))?;
            invite::unwrap_invite(member_keys, &wrap)?
        }
    };

    // Validated by unwrap_invite (shape + self-certifying community id +
    // role/secret coherence).
    let community_id = bundle.community_id.clone();
    if Keystore::exists(&community_id) {
        bail!("a keystore for community {community_id} already exists — refusing to overwrite");
    }
    let ks = bundle.into_keystore();

    // Holding the bundle must check out against the live world BEFORE we
    // publish anything: the 30640 must verify against the bundled tenant
    // pubkey, and the derived guestbook key must be in its aux set (otherwise
    // the node would bounce our join).
    let relay_url = ks.relays.first().context("invite carries no relay")?;
    let tenant_hex = ks.tenant_hex()?;
    let regs = relay::registration_candidates(relay_url, &ks.alias)?;
    let now = now_secs();
    let live = newest_valid_registration(regs, &tenant_hex, now)
        .ok_or_else(|| anyhow!("no valid live registration for the invited repo"))?;
    let gb_hex = ks.guestbook_keys()?.public_key().to_hex();
    if !parse_aux_keys(&live).contains(&gb_hex) {
        bail!(
            "the live registration does not list the guestbook stream key — \
             the invite is stale (secrets rotated?); ask for a fresh one"
        );
    }

    ks.save()?;
    publish_join(member_keys, &ks).context("keystore imported, but the guestbook join failed")?;
    Ok(community_id)
}

/// The roster as visible to this keystore: local grants + banlist + verified
/// guestbook joins fetched from the node.
pub struct RosterView {
    pub grants: Vec<RosterEntry>,
    pub banned: Vec<BanEntry>,
    pub joins: Vec<JoinInfo>,
}

/// Fetch + verify the guestbook joins for a community and pair them with the
/// locally-known grants.
pub fn roster(community_id: &str) -> Result<RosterView> {
    let ks = Keystore::load(community_id)?;
    let relay_url = ks.relays.first().context("no relay configured")?;
    let gb_hex = ks.guestbook_keys()?.public_key().to_hex();
    let wraps = relay::wraps_by_author(relay_url, &gb_hex)?;
    let mut joins = Vec::new();
    for wrap in &wraps {
        // parse_join verifies outer + inner signatures, the guestbook author,
        // and the cgc community binding; non-join guestbook rumors are skipped.
        if let Ok(info) = invite::parse_join(&ks, wrap) {
            joins.push(info);
        }
    }
    joins.sort_by_key(|j| j.at);
    joins.dedup_by(|a, b| a.member_pub == b.member_pub);
    Ok(RosterView {
        grants: ks.roster.clone(),
        banned: ks.banned.clone(),
        joins,
    })
}

// ---------------------------------------------------------------------------
// #collab: issues / PRs / comments (plan §2, §3.2; GitLab issue !2)
// ---------------------------------------------------------------------------

/// Retain the verbatim inner-rumor bytes (0600, flip-public), publish the outer
/// wrap, and confirm the node serves it back (OK=true is not a commit marker).
/// Returns the inner rumor id (the thread anchor).
fn publish_collab(ks: &Keystore, pubbed: &CollabPublish) -> Result<String> {
    let relay_url = ks.relays.first().context("no relay configured")?;

    // Retain the raw signed rumor BEFORE publishing (flip-public needs the
    // byte-exact JSON; re-serialization would break the id/signature).
    let dir = Keystore::community_dir(&ks.community_id)?.join("collab");
    std::fs::create_dir_all(&dir)?;
    crate::keystore::write_0600(
        &dir.join(format!("{}.json", pubbed.rumor_id)),
        &pubbed.raw,
    )?;

    let out = relay::publish(relay_url, &pubbed.wrap)?;
    if !out.accepted {
        bail!("#collab message rejected by node: {}", out.message);
    }
    let stored = relay::event_by_id(relay_url, &pubbed.wrap.id.to_hex())?;
    if !stored
        .iter()
        .any(|e| e.id == pubbed.wrap.id && e.verify().is_ok())
    {
        bail!("#collab message was accepted but is not served back by the node");
    }
    Ok(pubbed.rumor_id.clone())
}

/// Any member (read or write) can post #collab rumors — they are signed by the
/// author identity and admitted under the aux stream key. We only require that
/// this keystore actually belongs to the community (has the collab key).
fn load_collab_ks(repo_dir: &Path) -> Result<Keystore> {
    let community_id = read_pointer(repo_dir)?;
    Keystore::load(&community_id)
}

/// `cord-git issue new` — file an issue signed by `author`. Returns its id.
pub fn issue_new(
    repo_dir: &Path,
    author: &nostr::Keys,
    subject: &str,
    body: &str,
) -> Result<String> {
    let ks = load_collab_ks(repo_dir)?;
    let pubbed = collab::build_issue(author, &ks, subject, body)?;
    publish_collab(&ks, &pubbed)
}

/// `cord-git issue comment` — comment on `root_id`, optionally replying to a
/// specific message. Also used for PR review comments (same thread model).
pub fn issue_comment(
    repo_dir: &Path,
    author: &nostr::Keys,
    root_id: &str,
    reply_to: Option<&str>,
    body: &str,
) -> Result<String> {
    let ks = load_collab_ks(repo_dir)?;
    let pubbed = collab::build_comment(author, &ks, root_id, reply_to, body)?;
    publish_collab(&ks, &pubbed)
}

/// `cord-git issue close` — set the thread status to closed.
pub fn issue_close(
    repo_dir: &Path,
    author: &nostr::Keys,
    root_id: &str,
    note: &str,
) -> Result<String> {
    let ks = load_collab_ks(repo_dir)?;
    let pubbed = collab::build_status(author, &ks, root_id, Status::Closed, note)?;
    publish_collab(&ks, &pubbed)
}

/// `cord-git pr new` — build a patch series from a git revision range
/// (`git format-patch`), publish each patch as a 1617 rumor threaded under the
/// first, and return the PR root id.
pub fn pr_new(
    repo_dir: &Path,
    author: &nostr::Keys,
    range: &str,
    subject: &str,
) -> Result<String> {
    let ks = load_collab_ks(repo_dir)?;
    let patches = git::format_patch_range(repo_dir, range)?;
    if patches.is_empty() {
        bail!("revision range '{range}' contains no commits to send");
    }
    let mut root_id: Option<String> = None;
    for (i, patch) in patches.iter().enumerate() {
        let subj = format!("[PATCH {}/{}] {subject}", i + 1, patches.len());
        let pubbed = collab::build_patch(author, &ks, root_id.as_deref(), &subj, patch)?;
        let id = publish_collab(&ks, &pubbed)?;
        if root_id.is_none() {
            root_id = Some(id);
        }
    }
    Ok(root_id.expect("at least one patch published"))
}

/// `cord-git pr status` — set a PR/issue status (open/merged/closed/draft).
pub fn pr_status(
    repo_dir: &Path,
    author: &nostr::Keys,
    root_id: &str,
    status: Status,
    note: &str,
) -> Result<String> {
    let ks = load_collab_ks(repo_dir)?;
    let pubbed = collab::build_status(author, &ks, root_id, status, note)?;
    publish_collab(&ks, &pubbed)
}

/// Fetch, verify, and fold every readable #collab thread for a community.
/// Readable only back to the most recent rekey (the collab key rolls on
/// revoke) — see `collab::read_all`. Used by `issue/pr list` and `show`.
pub fn collab_threads(community_id: &str) -> Result<Vec<Thread>> {
    let ks = Keystore::load(community_id)?;
    let relay_url = ks.relays.first().context("no relay configured")?;
    let stream_hex = ks.guestbook_keys()?.public_key().to_hex();
    let wraps = relay::wraps_by_author(relay_url, &stream_hex)?;
    let events = collab::read_all(&ks, &wraps);
    Ok(collab::fold_threads(events))
}

/// `cord-git push` — pack all objects, encrypt, upload, publish a new 30641
/// under client-side CAS. Returns the new 30641 event id.
pub fn push(repo_dir: &Path, force: bool) -> Result<String> {
    let community_id = read_pointer(repo_dir)?;
    let mut ks = Keystore::load(&community_id)?;
    if !ks.is_write() {
        bail!("this repo is read-only for you (no write_secret)");
    }
    let relay_url = ks.relays.first().context("no relay configured")?.clone();
    let server_url = ks.servers.first().context("no blob server configured")?.clone();
    let tenant_hex = ks.tenant_hex()?;
    let write_keys = ks.write_keys()?;
    let state_key = ks.state_key_bytes()?;

    // CAS: the remote must be where we left it — using the AUTHENTICATED
    // latest (signature + current-write-key + freshness checked).
    let remote = latest_valid_state_root(&ks)?;
    let remote_id = remote.as_ref().map(|e| e.id.to_hex());
    if !force && remote_id != ks.manifest_prev {
        bail!(
            "remote moved — fetch/merge first (remote={:?}, local base={:?}). Use --force to override.",
            remote_id,
            ks.manifest_prev
        );
    }

    // Pack every object; encrypt under a fresh random key.
    let pack = git::pack_all(repo_dir)?;
    let enc = crypto::encrypt_blob_random(&pack)?;
    let pack_entry = PackEntry {
        blob_id: enc.blob_id.clone(),
        key: hex::encode(enc.key),
        nonce: hex::encode(enc.nonce),
        size: enc.wire.len() as u64,
    };

    // Build + encrypt the manifest under the #state key.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let manifest = Manifest {
        v: 1,
        community_id: community_id.clone(),
        epoch: ks.epoch,
        refs: git::branch_refs(repo_dir)?,
        packs: vec![pack_entry],
        manifest_prev: remote_id.clone(),
        ts: now,
    };
    let menc = crypto::encrypt_manifest(&state_key, &manifest.to_json())?;

    // Upload both blobs (24242-authed).
    let (_e, pack_auth) =
        events::build_blossom_auth(&write_keys, BlobOp::Upload, &enc.blob_id, &tenant_hex, &ks.alias)?;
    blob::put(&server_url, &enc.wire, &pack_auth)?;
    let (_e, man_auth) = events::build_blossom_auth(
        &write_keys,
        BlobOp::Upload,
        &menc.blob_id,
        &tenant_hex,
        &ks.alias,
    )?;
    blob::put(&server_url, &menc.wire, &man_auth)?;

    // Publish the public 30641 anchor.
    let state = events::build_state_root(
        &write_keys,
        &tenant_hex,
        &ks.alias,
        &menc.blob_id,
        menc.wire.len() as u64,
        &manifest.packs,
    )?;
    let out = relay::publish(&relay_url, &state)?;
    if !out.accepted {
        bail!("state root (30641) rejected: {}", out.message);
    }

    // Post-publish confirmation: OK=true does NOT mean our edition won the
    // (author, alias) coordinate — the relay stores only the newest, and the
    // policy can accept an edition the DB then discards (stale/lost race).
    // Read back and verify OUR event is the served latest before claiming
    // success; otherwise manifest_prev would record a phantom.
    let confirmed = latest_valid_state_root(&ks)?;
    let confirmed_id = confirmed.as_ref().map(|e| e.id.to_hex());
    let new_id = state.id.to_hex();
    if confirmed_id.as_deref() != Some(new_id.as_str()) {
        bail!(
            "push lost the race: our 30641 was accepted but is not the served latest \
             (latest={confirmed_id:?}). Another writer won — re-clone and re-apply your changes."
        );
    }

    ks.manifest_prev = Some(new_id.clone());
    ks.save()?;
    Ok(new_id)
}

/// Fetch + decrypt the remote manifest for this keystore (None if the repo
/// was registered but never pushed).
fn remote_manifest(ks: &Keystore) -> Result<Option<Manifest>> {
    let Some(state) = latest_valid_state_root(ks)? else {
        return Ok(None);
    };
    let server_url = ks.servers.first().context("no blob server configured")?;
    let m_hash = tag_value(&state, "m").ok_or_else(|| anyhow!("30641 missing m tag"))?;
    let wire = blob::get(server_url, &m_hash)?;
    if crypto::sha256_hex(&wire) != m_hash {
        bail!("manifest blob hash mismatch — operator served wrong bytes");
    }
    let json = crypto::decrypt_manifest(&ks.state_key_bytes()?, &wire)?;
    Ok(Some(Manifest::from_json(&json)?))
}

/// `cord-git rotate` — revocation primitive. Generate a fresh `write_secret`
/// and `#state` key, re-register the 30640 with ONLY the new write key (freeing
/// the old key server-side), and re-push the current state under the new
/// secrets. Anyone who held the old secrets can no longer push (their write key
/// is deregistered) nor read new content (new `#state` key); their existing
/// clone keeps working (forward-only, C7). Retained members are re-provisioned
/// with the new secrets out-of-band (invite flow — Phase 4-full).
///
/// Returns the new 30641 event id.
pub fn rotate(repo_dir: &Path) -> Result<String> {
    let community_id = read_pointer(repo_dir)?;
    let mut ks = Keystore::load(&community_id)?;
    if !ks.is_write() {
        bail!("only a write member can rotate/revoke");
    }
    if load_pending(&community_id)?.is_some() {
        bail!(
            "an interrupted rotation is still pending — complete it first \
             (rerun the revoke/demote command) before rotating again"
        );
    }
    let relay_url = ks.relays.first().context("no relay configured")?.clone();
    let hosting = ks.hosting_keys()?;

    freshness_guard(repo_dir, &ks)?;

    let new_write_secret = crypto::random_32();
    let new_state_key = crypto::random_32();
    let new_write_keys = crypto::derive_write_keys(&new_write_secret, ks.epoch)?;

    // Re-register with the new write key only; the server frees the old key's
    // claim, so a 30641 signed by the old key is rejected thereafter. The
    // guestbook aux key stays (derived from #collab, which rotate does not
    // roll — full collab rekey is the Phase 4-full refounding).
    let guestbook = ks.guestbook_keys()?;
    let reg = events::build_registration(
        &hosting,
        &new_write_keys,
        &[&guestbook],
        &ks.alias,
        &ks.relays,
        &ks.servers,
    )?;
    let out = relay::publish(&relay_url, &reg)?;
    if !out.accepted {
        bail!("re-registration (rotation) rejected: {}", out.message);
    }

    ks.write_secret = Some(hex::encode(new_write_secret));
    ks.state_key = hex::encode(new_state_key);
    // The new write key is a fresh (author, alias) coordinate → fresh CAS chain.
    ks.manifest_prev = None;
    ks.save()?;

    // Re-push current state under the new secrets (force: fresh chain).
    push(repo_dir, true)
}

/// Refuse to rotate/refound when the LOCAL WORKING TREE's refs differ from
/// the remote manifest's refs: these flows re-publish the local checkout
/// under new secrets, so running them from a stale checkout would silently
/// roll back every reader. (Comparing refs, not the keystore anchor — another
/// clone may have moved the keystore past this checkout.)
fn freshness_guard(repo_dir: &Path, ks: &Keystore) -> Result<()> {
    match remote_manifest(ks)? {
        None => Ok(()), // never pushed — nothing to be behind
        Some(m) => {
            let local_refs = git::branch_refs(repo_dir)?;
            if m.refs != local_refs {
                bail!(
                    "refusing to rotate: this checkout's refs differ from the remote — \
                     re-clone (or fast-forward) first"
                );
            }
            Ok(())
        }
    }
}

/// Publish a 30640 edition to ONE relay and confirm — via an EOSE-terminated
/// read-back — that it is the served latest THERE. OK=true is not a commit
/// marker (addressable replacement can discard a stale edition, and a node
/// may accept-then-lose a race).
fn publish_registration_confirmed_on(
    relay_url: &str,
    ks: &Keystore,
    reg: &nostr::Event,
) -> Result<()> {
    let tenant_hex = ks.tenant_hex()?;
    let out = relay::publish(relay_url, reg)
        .with_context(|| format!("publishing 30640 to {relay_url}"))?;
    if !out.accepted {
        bail!("registration rejected by {relay_url}: {}", out.message);
    }
    let regs = relay::registration_candidates(relay_url, &ks.alias)
        .with_context(|| format!("read-back from {relay_url}"))?;
    let newest = newest_valid_registration(regs, &tenant_hex, now_secs())
        .ok_or_else(|| anyhow!("no valid registration served back by {relay_url}"))?;
    if newest.id != reg.id {
        bail!("registration edition is not the served latest on {relay_url}");
    }
    Ok(())
}

/// §3.3 step 4: publish one refounding artifact (rekey wrap) to the listed
/// relays. Callers run this only on relays already brought to widen-live
/// (the §3.3 ordering invariant, enforced per relay by
/// [`run_pending_rotation`]). Retains the raw inner rumor bytes (0600, flip
/// discipline) BEFORE publishing, and read-back-confirms on each relay.
/// An "unregistered key" rejection runs `on_unregistered` once per relay
/// (to add the rekey address to that relay's registration — covers the
/// un-squatted case of a squat-tolerant minimal widen, verify-round F-B) and
/// the publish retries once. ANY OTHER rejection (quota, policy) is fatal
/// with the server's message — it is not widenable and must not be masked
/// (a squatter exhausting their own quota shows up exactly this way and
/// needs operator remediation, not a doomed retry).
fn publish_rekey_wrap(
    wrap: &nostr::Event,
    raw: &[u8],
    relays: &[String],
    community_id: &str,
    mut on_unregistered: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let dir = Keystore::community_dir(community_id)?.join("rekeys");
    std::fs::create_dir_all(&dir)?;
    crate::keystore::write_0600(&dir.join(format!("{}.json", wrap.id.to_hex())), raw)?;
    for relay_url in relays {
        let out = relay::publish(relay_url, wrap)
            .with_context(|| format!("publishing rekey wrap to {relay_url}"))?;
        if !out.accepted {
            if out.message.contains("unregistered") {
                on_unregistered(&wrap.pubkey.to_hex())?;
                let retry = relay::publish(relay_url, wrap)
                    .with_context(|| format!("republishing rekey wrap to {relay_url}"))?;
                if !retry.accepted {
                    bail!("rekey wrap rejected by {relay_url}: {}", retry.message);
                }
            } else {
                bail!(
                    "rekey wrap rejected by {relay_url}: {} (not an admission-listing issue — \
                     check the claiming tenant's quota/operator action)",
                    out.message
                );
            }
        }
    }
    // Id-pinned read-back: the genuine wrap is past-tweaked (up to 2 days
    // back), so an author-scoped read can lose it to a flood of now-dated
    // junk wraps at the same address (GitLab !13).
    for relay_url in relays {
        let stored = relay::event_by_id(relay_url, &wrap.id.to_hex())?;
        if !stored.iter().any(|e| e.id == wrap.id && e.verify().is_ok()) {
            bail!("rekey wrap accepted but not served back by {relay_url}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Idempotent epoch rotations (GitLab !14)
// ---------------------------------------------------------------------------
//
// revoke/demote used to publish the rekeys + narrow BEFORE saving the
// refounded secrets; a crash in between made a retry mint a SECOND genuine
// rekey set at the same deterministic addresses, forking the membership.
// Now the ENTIRE rotation — secrets, roster/banlist snapshots, and the built
// artifacts (widen, rekey wraps, narrow) — is persisted to
// `pending-epoch.json` (0600) BEFORE anything is published. A retry resumes
// from the file and republishes the SAME bytes (relay dedups by id), so one
// epoch can never have two genuine rekey sets.

/// One built rekey artifact retained in the pending file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingRekey {
    scope: String,
    wrap_json: String,
    raw_b64: String,
}

/// A fully-built, not-yet-completed epoch rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingEpoch {
    v: u32,
    /// "revoke" or "demote".
    kind: String,
    /// The banned/demoted member identity hex.
    target: String,
    old_epoch: u32,
    new_epoch: u32,
    /// Post-mutation roster + banlist snapshots (applied on adoption).
    roster: Vec<RosterEntry>,
    banned: Vec<BanEntry>,
    /// Refounded secrets; `None` for fields this rotation does not roll
    /// (demote rolls only the write secret).
    community_root: Option<String>,
    state_key: Option<String>,
    collab_key: Option<String>,
    write_secret: String,
    /// The PRIOR community root (hex) — the rekey addresses derive from it;
    /// needed by the rival-resume guard even after local adoption.
    #[serde(default)]
    prior_root: Option<String>,
    widen_json: String,
    narrow_json: String,
    rekeys: Vec<PendingRekey>,
}

fn pending_path(community_id: &str) -> Result<std::path::PathBuf> {
    Ok(Keystore::community_dir(community_id)?.join("pending-epoch.json"))
}

fn load_pending(community_id: &str) -> Result<Option<PendingEpoch>> {
    let path = pending_path(community_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)
        .with_context(|| format!("cannot read pending rotation file {path:?}"))?;
    let p: PendingEpoch = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "pending rotation file {path:?} is corrupt — refusing to guess; inspect it \
             manually (it holds the interrupted epoch's secrets). Do NOT simply delete it \
             and retry: if that rotation's rekeys were published, re-minting forks the \
             membership (GitLab !14)"
        )
    })?;
    if p.v != 1 {
        bail!("pending rotation file has an unknown version");
    }
    Ok(Some(p))
}

/// Persist the pending rotation BEFORE anything is published (atomic:
/// tmp + rename, 0600 from creation).
fn save_pending(p: &PendingEpoch, community_id: &str) -> Result<()> {
    let path = pending_path(community_id)?;
    let json = serde_json::to_vec_pretty(p)?;
    let tmp = path.with_extension("json.tmp");
    crate::keystore::write_0600(&tmp, &json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

fn delete_pending(community_id: &str) -> Result<()> {
    let path = pending_path(community_id)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("cannot delete the pending rotation file"),
    }
}

/// TEST-ONLY crash hook (`CORD_GIT_ALLOW_DEBUG=1` + `CORD_GIT_DEBUG_ABORT_AFTER=
/// widen|rekey:state|rekey:collab|rekey:write|narrow`): bail right after the
/// named step, simulating a crash mid-rotation. e2e uses it to prove the
/// pending-file resume mints no second rekey set (GitLab !14) and that folds
/// refuse partial epochs (GitLab !12).
fn debug_abort_point(step: &str) -> Result<()> {
    if std::env::var("CORD_GIT_ALLOW_DEBUG").as_deref() == Ok("1")
        && std::env::var("CORD_GIT_DEBUG_ABORT_AFTER").as_deref() == Ok(step)
    {
        bail!("debug abort after {step} (CORD_GIT_DEBUG_ABORT_AFTER)");
    }
    Ok(())
}

/// The newest signature-valid, tenant-authored 30640 for this keystore's
/// alias across ALL configured relays (a withholding relay must not be able
/// to hide a rotation — GitLab !12/!14).
fn live_registration(ks: &Keystore) -> Result<Option<nostr::Event>> {
    let tenant_hex = ks.tenant_hex()?;
    let filter = serde_json::json!({ "kinds": [30640], "#d": [ks.alias], "limit": 8 });
    let regs = relay::fetch_all_multi(&ks.relays, filter)?;
    Ok(newest_valid_registration(regs, &tenant_hex, now_secs()))
}

/// Single-relay variant of [`live_registration`] — per-relay rotation state
/// (verify F2: union-liveness must never stand in for "live everywhere").
fn live_registration_on(relay_url: &str, ks: &Keystore) -> Result<Option<nostr::Event>> {
    let tenant_hex = ks.tenant_hex()?;
    let regs = relay::registration_candidates(relay_url, &ks.alias)?;
    Ok(newest_valid_registration(regs, &tenant_hex, now_secs()))
}

/// Rebuild a 30640 from a pending-file TEMPLATE (its tags carry every
/// pubkey + proof-of-possession, which bind only (tenant, alias) and stay
/// valid) with a FRESH created_at, re-signed by the hosting key. Registrations
/// are rebuilt per relay per attempt with `created_at = live.created_at + 1`,
/// which eliminates the whole class of addressable-replacement tie-break
/// wedges (same-second lowest-id ties, backward clock steps, skewed-second
/// machines) — only the secret-bearing rekey wraps must stay byte-identical.
fn rebuild_registration(
    template_json: &str,
    drop_aux_pubkeys: &[String],
    hosting: &nostr::Keys,
    created_at: u64,
) -> Result<nostr::Event> {
    use nostr::prelude::FinalizeEvent;
    let template =
        nostr::Event::from_json(template_json).context("pending registration template is not an event")?;
    template
        .verify()
        .map_err(|e| anyhow!("pending registration template fails signature verification: {e}"))?;
    let tags: Vec<nostr::Tag> = template
        .tags
        .iter()
        .filter(|t| {
            let v = (*t).clone().to_vec();
            !(v.len() >= 2 && v[0] == "aux" && drop_aux_pubkeys.contains(&v[1]))
        })
        .cloned()
        .collect();
    let event = nostr::EventBuilder::new(nostr::Kind::Custom(30640), "")
        .tags(tags)
        .custom_created_at(nostr::Timestamp::from_secs(created_at))
        .finalize(hosting)?;
    Ok(event)
}

/// Do a live registration's w/aux pubkey sets match a template's exactly?
fn registration_key_sets_match(live: &nostr::Event, template: &nostr::Event) -> bool {
    let set = |ev: &nostr::Event, name: &str| -> std::collections::BTreeSet<String> {
        ev.tags
            .iter()
            .filter_map(|t| {
                let v = t.clone().to_vec();
                if v.len() >= 2 && v[0] == name {
                    Some(v[1].clone())
                } else {
                    None
                }
            })
            .collect()
    };
    set(live, "w") == set(template, "w") && set(live, "aux") == set(template, "aux")
}

/// Is `live` one of this rotation's own widen variants? The full widen or
/// any squat-tolerant/on-demand variant (same w set; aux = template aux
/// minus ANY subset of the rekey addresses).
fn registration_is_widen_variant(
    live: &nostr::Event,
    template: &nostr::Event,
    rekey_addr_pubs: &[String],
) -> bool {
    let set = |ev: &nostr::Event, name: &str| -> std::collections::BTreeSet<String> {
        ev.tags
            .iter()
            .filter_map(|t| {
                let v = t.clone().to_vec();
                if v.len() >= 2 && v[0] == name {
                    Some(v[1].clone())
                } else {
                    None
                }
            })
            .collect()
    };
    if set(live, "w") != set(template, "w") {
        return false;
    }
    let template_aux = set(template, "aux");
    let live_aux = set(live, "aux");
    let floor: std::collections::BTreeSet<String> = template_aux
        .iter()
        .filter(|a| !rekey_addr_pubs.contains(a))
        .cloned()
        .collect();
    floor.is_subset(&live_aux) && live_aux.is_subset(&template_aux)
}

/// Publish a registration variant to one relay, tolerating a cross-alias
/// SQUAT on the rekey addresses (verify-round F-B): a member can derive every
/// epoch's rekey addresses and claim them under their OWN alias, which makes
/// the server reject the full widen ("write key already registered"). The
/// rekey wraps at a squatted address are still admitted (charged to the
/// SQUATTER's quota), so the rotation only needs the widen for the w-set and
/// the non-squatted addresses. Fallback: strip ALL rekey addresses (the only
/// derivable, therefore squattable, keys — w/guestbook keys are random and
/// can never conflict) and proceed; non-squatted rekey addresses are added
/// back on demand when a rekey publish comes back "unregistered".
fn publish_widen_variant_on(
    relay_url: &str,
    ks: &Keystore,
    template_json: &str,
    rekey_addr_pubs: &[String],
    hosting: &nostr::Keys,
    created_at: u64,
) -> Result<()> {
    let full = rebuild_registration(template_json, &[], hosting, created_at)?;
    match publish_registration_confirmed_on(relay_url, ks, &full) {
        Ok(()) => Ok(()),
        Err(e) if format!("{e:#}").contains("write key already registered") => {
            eprintln!(
                "a rekey address for this epoch is already registered by another alias on \
                 {relay_url} (squatted or stale) — publishing the widen without the rekey \
                 addresses; the rekey wraps are admitted under the squatter's registration"
            );
            let minimal = rebuild_registration(template_json, rekey_addr_pubs, hosting, created_at)?;
            publish_registration_confirmed_on(relay_url, ks, &minimal).with_context(|| {
                format!(
                    "30640-prime (minimal widen) was not accepted on {relay_url} — \
                     refusing to publish any refounding artifact"
                )
            })
        }
        Err(e) => Err(e),
    }
}

/// Execute a persisted rotation idempotently PER RELAY (verify F2): every
/// configured relay is brought to widen-live independently before any rekey
/// is sent to it (a widen live on only some relays is republished to the
/// laggards; rekeys go only to widen-confirmed relays; the narrow must end
/// as the served latest on EVERY relay — otherwise revocation never lands
/// on the laggard, a silent bypass). Registrations are rebuilt from the
/// pending templates with per-relay created_at (live+1), so resume works
/// after any delay and never hits replacement tie-breaks; only the rekey
/// wraps republish byte-identically (relay dedups by id). Then adopt the
/// secrets, save, drop the pending file, and push the post-rotation
/// snapshot.
fn run_pending_rotation(repo_dir: &Path, ks: &Keystore, p: &PendingEpoch) -> Result<String> {
    let hosting = ks.hosting_keys()?;
    let widen_template =
        nostr::Event::from_json(&p.widen_json).context("pending widen is not an event")?;
    widen_template
        .verify()
        .map_err(|e| anyhow!("pending widen fails signature verification: {e}"))?;
    let narrow_template =
        nostr::Event::from_json(&p.narrow_json).context("pending narrow is not an event")?;
    narrow_template
        .verify()
        .map_err(|e| anyhow!("pending narrow fails signature verification: {e}"))?;

    // Parse + verify the rekey wraps once (frozen, byte-identical).
    let mut rekeys: Vec<(String, nostr::Event, Vec<u8>)> = Vec::new();
    let mut rekey_addr_pubs: Vec<String> = Vec::new();
    for pr in &p.rekeys {
        let wrap =
            nostr::Event::from_json(&pr.wrap_json).context("pending rekey wrap is not an event")?;
        wrap.verify()
            .map_err(|e| anyhow!("pending rekey wrap fails signature verification: {e}"))?;
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &pr.raw_b64)
            .context("pending rekey raw bytes are not base64")?;
        rekey_addr_pubs.push(wrap.pubkey.to_hex());
        rekeys.push((pr.scope.clone(), wrap, raw));
    }

    // Phase 1 (ALL relays first, §3.3): every relay that is not already
    // narrow-live must be brought to widen-live — squat-tolerant per relay.
    // No refounding artifact may be published before the widen is confirmed
    // on EVERY node.
    //
    // Rival-resume guard (verify round 4/5): before publishing over a
    // registration that is NONE of this rotation's own artifacts, check its
    // created_at: anything NEWER than the widen template that is neither the
    // pre-rotation registration nor one of this rotation's widen variants is
    // a RIVAL rotation that landed after this pending file was written (the
    // two-device case: device 1 crashes, device 2 restores a keystore backup
    // and completes). Resuming would regress the live registration to the
    // stale epoch's keys. Note the trigger is the landed registration, never
    // a stray genuine rekey wrap — a poisoned wrap inside the widen window
    // is the fold-side Fork rule's job, not this one's.
    let mut widen_live_relays: Vec<String> = Vec::new();
    for relay_url in &ks.relays {
        let live = live_registration_on(relay_url, ks).with_context(|| {
            format!(
                "cannot read the live registration from {relay_url} — \
                 refusing to publish any refounding artifact"
            )
        })?;
        if live
            .as_ref()
            .is_some_and(|l| registration_key_sets_match(l, &narrow_template))
        {
            continue; // rotation fully landed here already
        }
        let is_ours = live.as_ref().is_some_and(|l| {
            registration_is_widen_variant(l, &widen_template, &rekey_addr_pubs)
        });
        if !is_ours {
            if let Some(l) = &live {
                if l.created_at.as_secs() > widen_template.created_at.as_secs() {
                    bail!(
                        "the live registration on {relay_url} is newer than this pending \
                         rotation and matches none of its artifacts — a rival rotation \
                         landed ELSEWHERE (another device?). Run `cord-git fold` to adopt \
                         it, then delete the pending file; refusing to regress the \
                         registration to the stale epoch (the !14 fork)"
                    );
                }
            }
            let at = live
                .as_ref()
                .map(|l| l.created_at.as_secs() + 1)
                .unwrap_or_else(now_secs);
            publish_widen_variant_on(
                relay_url,
                ks,
                &p.widen_json,
                &rekey_addr_pubs,
                &hosting,
                at,
            )?;
        }
        widen_live_relays.push(relay_url.clone());
    }
    debug_abort_point("widen")?;

    // Phase 2 (per relay): rekeys, then narrow. A rekey rejected as
    // "unregistered" means its address is neither squatted nor listed —
    // add JUST that address to this relay's registration (conflict-free)
    // and retry. Additions are cumulative (replacement would otherwise
    // deregister an earlier addition). If the addition itself hits a key
    // conflict, the address was (re-)squatted in the meantime — which also
    // means the rekey is admitted under the squatter's registration, so
    // skipping the addition is correct.
    for relay_url in &widen_live_relays {
        let mut added: Vec<String> = Vec::new();
        let mut squatted: Vec<String> = Vec::new();
        for (scope, wrap, raw) in &rekeys {
            publish_rekey_wrap(wrap, raw, std::slice::from_ref(relay_url), &ks.community_id, |missing_addr| {
                if squatted.iter().any(|a| a == missing_addr) {
                    return Ok(());
                }
                added.push(missing_addr.to_string());
                let live_now = live_registration_on(relay_url, ks)?;
                let at = live_now
                    .as_ref()
                    .map(|l| l.created_at.as_secs() + 1)
                    .unwrap_or_else(now_secs);
                let drop: Vec<String> = rekey_addr_pubs
                    .iter()
                    .filter(|a| !added.contains(a))
                    .cloned()
                    .collect();
                let widened = rebuild_registration(&p.widen_json, &drop, &hosting, at)?;
                match publish_registration_confirmed_on(relay_url, ks, &widened) {
                    Ok(()) => Ok(()),
                    Err(e) if format!("{e:#}").contains("write key already registered") => {
                        added.retain(|a| a != missing_addr);
                        squatted.push(missing_addr.to_string());
                        Ok(())
                    }
                    Err(e) => Err(e).with_context(|| {
                        format!("on-demand widen (adding a rekey address) failed on {relay_url}")
                    }),
                }
            })?;
            debug_abort_point(&format!("rekey:{scope}"))?;
        }
        let live_now = live_registration_on(relay_url, ks)?;
        let at = live_now
            .as_ref()
            .map(|l| l.created_at.as_secs() + 1)
            .unwrap_or_else(now_secs);
        let narrow = rebuild_registration(&p.narrow_json, &[], &hosting, at)?;
        publish_registration_confirmed_on(relay_url, ks, &narrow)
            .context("30640-double-prime (narrow) failed after the rekeys were published")?;
        debug_abort_point("narrow")?;
    }

    // Final verification sweep (verify-round sync-collision): per-relay
    // created_at chains can tie cross-relay (an on-demand widen-stage edition
    // and a narrow sharing a second), and GRASP sync may transiently serve a
    // widen-stage edition over the narrow on a laggard. Re-read every relay
    // and re-narrow anything not serving the narrow's key sets — closing the
    // "revocation never landed on the laggard" window deterministically.
    for relay_url in &ks.relays {
        let live = live_registration_on(relay_url, ks)?;
        if live
            .as_ref()
            .is_some_and(|l| registration_key_sets_match(l, &narrow_template))
        {
            continue;
        }
        let at = live
            .as_ref()
            .map(|l| l.created_at.as_secs() + 1)
            .unwrap_or_else(now_secs);
        let narrow = rebuild_registration(&p.narrow_json, &[], &hosting, at)?;
        publish_registration_confirmed_on(relay_url, ks, &narrow)
            .context("final narrow sweep failed")?;
    }

    // Adopt the refounded secrets; the new write key is a fresh (author,
    // alias) coordinate → fresh CAS chain.
    let mut ks = Keystore::load(&ks.community_id)?;
    if let Some(root) = &p.community_root {
        ks.community_root = Some(root.clone());
    }
    if let Some(sk) = &p.state_key {
        ks.state_key = sk.clone();
    }
    if let Some(ck) = &p.collab_key {
        ks.collab_key = ck.clone();
    }
    ks.write_secret = Some(p.write_secret.clone());
    ks.roster = p.roster.clone();
    ks.banned = p.banned.clone();
    ks.epoch = p.new_epoch;
    ks.manifest_prev = None;
    ks.save()?;
    delete_pending(&ks.community_id)?;

    // The refounding snapshot: re-push the current state under new secrets.
    push(repo_dir, true)
}

/// Outcome of the interrupted-rotation gate at revoke/demote entry.
#[derive(Debug)]
enum PendingGate {
    /// No pending rotation (or only a fully-consumed one).
    None,
    /// An identical rotation is pending — resume it byte-identically.
    Resume(Box<PendingEpoch>),
    /// The pending rotation was already ADOPTED (crash between the keystore
    /// save and the pending-file cleanup) — only the trailing snapshot push
    /// is still owed.
    Completed,
}

/// Gate entry to revoke/demote on any interrupted rotation. Returns the
/// pending rotation to RESUME when it matches this command (same kind +
/// target); bails with guidance otherwise.
fn pending_gate(ks: &Keystore, kind: &str, target: &str) -> Result<PendingGate> {
    let Some(p) = load_pending(&ks.community_id)? else {
        return Ok(PendingGate::None);
    };
    if p.new_epoch == ks.epoch {
        // The rotation was adopted locally. Did it fully LAND (the narrow's
        // key sets the served latest on EVERY configured relay — never a
        // union check, which would let a laggard relay keep the old keys
        // admitted silently, verify-round F3)? Only then is it Complete: an
        // owner who recovered via fold after a crash-before-narrow holds the
        // adopted keystore while some relay sits at the widen — resuming
        // (not deleting the file) is what finishes the rotation there.
        let narrow_template =
            nostr::Event::from_json(&p.narrow_json).context("pending narrow is not an event")?;
        let mut landed_everywhere = true;
        for relay_url in &ks.relays {
            let live = live_registration_on(relay_url, ks).with_context(|| {
                format!("cannot read the live registration from {relay_url}")
            })?;
            if !live
                .as_ref()
                .is_some_and(|l| registration_key_sets_match(l, &narrow_template))
            {
                landed_everywhere = false;
                break;
            }
        }
        if landed_everywhere {
            delete_pending(&ks.community_id)?;
            return Ok(PendingGate::Completed);
        }
        if p.kind != kind || p.target != target {
            bail!(
                "an interrupted {} rotation to epoch {} (target {}) was adopted locally but \
                 its narrow never landed on every node — rerun `cord-git {} {}` to finish it \
                 before starting another rotation",
                p.kind,
                p.new_epoch,
                p.target,
                p.kind,
                p.target
            );
        }
        eprintln!(
            "the pending rotation to epoch {} was adopted locally but its narrow never \
             landed on every node — resuming to finish publishing it",
            p.new_epoch
        );
        return Ok(PendingGate::Resume(Box::new(p)));
    }
    if p.old_epoch != ks.epoch {
        bail!(
            "an interrupted rotation to epoch {} exists but this keystore is at epoch {} — \
             the keystore and the pending file disagree; restore a backup or inspect {} \
             (do NOT delete it and retry blindly: if that rotation's rekeys were published, \
             re-minting forks the membership — GitLab !14)",
            p.new_epoch,
            ks.epoch,
            pending_path(&ks.community_id)?.display()
        );
    }
    if p.kind != kind || p.target != target {
        bail!(
            "an interrupted {} rotation to epoch {} (target {}) is still pending — \
             rerun `cord-git {} {}` to complete it before starting another rotation \
             (retrying with fresh secrets is exactly the membership fork GitLab !14 fixes)",
            p.kind,
            p.new_epoch,
            p.target,
            p.kind,
            p.target
        );
    }
    eprintln!(
        "resuming the interrupted rotation to epoch {} — republishing the persisted \
         artifacts byte-identically (no second rekey set is minted)",
        p.new_epoch
    );
    Ok(PendingGate::Resume(Box::new(p)))
}

/// Fork PREVENTION at mint time (verify F6): before building a NEW rotation
/// to `new_epoch`, check whether genuine tenant-signed rekeys for that epoch
/// already exist at the derived addresses. If they do, a rotation is in
/// progress or was completed ELSEWHERE — another machine, a restored backup,
/// or a concurrent process (all states the local pending file cannot see).
/// Minting a rival set is exactly the GitLab !14 membership fork, so refuse.
fn ensure_no_existing_rekeys(ks: &Keystore, hosting: &nostr::Keys, new_epoch: u32) -> Result<()> {
    let root = ks.community_root_bytes()?;
    let tenant_hex = ks.tenant_hex()?;
    let prior_secret = ks.write_secret_bytes()?;
    let prior_write = prior_secret.as_ref().map(|s| (s, ks.epoch));
    for scope in Scope::all() {
        let addr = rekey::rekey_address(&root, &ks.community_id, scope, new_epoch)?;
        let filter = serde_json::json!({
            "kinds": [rekey::KIND_WRAP],
            "authors": [addr.public_key().to_hex()],
        });
        let wraps = relay::fetch_all_multi(&ks.relays, filter)?;
        for wrap in &wraps {
            if rekey::parse_rekey(
                wrap,
                &ks.community_id,
                &tenant_hex,
                &root,
                scope,
                new_epoch,
                hosting,
                prior_write,
            )
            .is_ok()
            {
                bail!(
                    "genuine {}-scope rekeys for epoch {new_epoch} already exist — a rotation \
                     is in progress or was completed ELSEWHERE (another machine, a restored \
                     backup, or a concurrent process). Run `cord-git fold` to adopt it, or \
                     resume it from where it was started. Refusing to mint a rival rekey set \
                     (the GitLab !14 fork)",
                    scope.name()
                );
            }
        }
    }
    Ok(())
}

/// `cord-git revoke <npub>` — plan §4: Banlist entry → refounding → §3.3
/// rotation sequencing → post-refounding snapshot push.
///
/// Native-layer refounding: roll the community root + both channel keys +
/// the write secret ("compact" has nothing to fold beyond the manifest — the
/// snapshot IS the final re-push); the Control republish (roster + banlist)
/// rides inside the state-scope rekey slots. Removed member keeps their old
/// clone (C7, forward-only): exclusion lands at the first post-rotation push
/// — nothing is re-encrypted.
///
/// Ordering (§3.3, NORMATIVE): 30640′ w=old∪new, aux=old∪new∪rekey-addrs
/// (this epoch's, from the prior root) → wait for acceptance on ALL nodes →
/// rekey 3303s at their per-scope addresses (write scope at its DEDICATED
/// address) → 30640″ with new-only sets → re-push.
///
/// GitLab !14: the whole rotation (secrets, roster/banlist snapshots, built
/// widen/rekeys/narrow) is persisted to `pending-epoch.json` BEFORE anything
/// is published, and a retried revoke RESUMES from it — an aborted rotation
/// can never mint a second genuine rekey set at the same addresses. The
/// owner identity is included in the rekey slots so the owner can recover
/// via `fold` even after losing local state.
pub fn revoke(repo_dir: &Path, banned_npub: &str) -> Result<String> {
    let community_id = read_pointer(repo_dir)?;
    let ks = Keystore::load(&community_id)?;
    if !ks.is_owner() {
        bail!("only the repo owner (hosting-key holder) can revoke");
    }
    if !ks.is_write() {
        bail!("owner keystore is missing the write secret");
    }
    let hosting = ks.hosting_keys()?;
    let banned_pk = nostr::PublicKey::parse(banned_npub)
        .map_err(|e| anyhow!("invalid npub to revoke: {e}"))?;
    let banned_hex = banned_pk.to_hex();
    if banned_hex == ks.tenant_hex()? {
        bail!("refusing to revoke the owner identity");
    }
    freshness_guard(repo_dir, &ks)?;

    // GitLab !14: resume an interrupted identical rotation instead of
    // minting anything new. Completed = a stale, already-adopted pending
    // file (crash between keystore save and file cleanup) — cleaned up by
    // the gate; fall through and let THIS command do its own rotation (its
    // trailing push also covers the interrupted one's snapshot).
    match pending_gate(&ks, "revoke", &banned_hex)? {
        PendingGate::Resume(p) => return run_pending_rotation(repo_dir, &ks, &p),
        PendingGate::Completed | PendingGate::None => {}
    }
    // Crash between the pending-file cleanup and the trailing push (or a
    // repeat command): the target is already banned in an adopted rotation —
    // only the snapshot push is owed, never a second epoch for the same ban.
    if ks.banned.iter().any(|b| b.npub == banned_hex)
        && !ks.roster.iter().any(|e| e.npub == banned_hex)
    {
        return push(repo_dir, true)
            .context("completing the trailing push of an already-adopted revoke");
    }

    let prior_root = ks.community_root_bytes()?;
    let old_epoch = ks.epoch;
    let new_epoch = old_epoch.checked_add(1).context("epoch overflow")?;
    ensure_no_existing_rekeys(&ks, &hosting, new_epoch)?;
    let old_write_secret = ks
        .write_secret_bytes()?
        .context("owner keystore is missing the write secret")?;
    let old_write_keys = ks.write_keys()?;
    let old_guestbook = ks.guestbook_keys()?;

    // The widen/narrow are built as TEMPLATES now (persisted in the pending
    // file): at publish time each is rebuilt per relay with created_at =
    // live.created_at + 1 (see run_pending_rotation), so no same-second
    // addressable-replacement tie-break is possible and resume works after
    // any delay.

    // Banlist entry + roster fold as SNAPSHOTS — the keystore itself is
    // mutated only when the rotation adopts (never before, so an aborted
    // rotation leaves no half-applied state).
    let mut new_roster = ks.roster.clone();
    new_roster.retain(|e| e.npub != banned_hex);
    let mut new_banned = ks.banned.clone();
    new_banned.retain(|b| b.npub != banned_hex);
    new_banned.push(BanEntry {
        npub: banned_hex.clone(),
        banned_at: now_secs(),
    });

    // Refounding: fresh root, channel keys, write secret — never reused.
    let new_root = crypto::random_32();
    let new_state_key = crypto::random_32();
    let new_collab_key = crypto::random_32();
    let new_write_secret = crypto::random_32();
    let new_write_keys = crypto::derive_write_keys(&new_write_secret, new_epoch)?;
    let new_guestbook = crypto::derive_guestbook_keys(&new_collab_key)?;

    // Rekey addresses for THIS rotation (epoch+1, derived from the PRIOR
    // root so retained members can find them). Next-epoch addresses are NOT
    // precomputed/pre-registered (GitLab !13): a rekey address is listed
    // ONLY between its widen and its narrow.
    let addr_state = rekey::rekey_address(&prior_root, &community_id, Scope::State, new_epoch)?;
    let addr_collab = rekey::rekey_address(&prior_root, &community_id, Scope::Collab, new_epoch)?;
    let addr_write = rekey::rekey_address(&prior_root, &community_id, Scope::Write, new_epoch)?;

    // §3.3 step 2: 30640′ — w = old ∪ new, aux = old ∪ new ∪ THIS epoch's
    // rekey addresses (and nothing else).
    let widen = events::build_registration_keysets(
        &hosting,
        &[&old_write_keys, &new_write_keys],
        &[
            &old_guestbook,
            &new_guestbook,
            &addr_state,
            &addr_collab,
            &addr_write,
        ],
        &ks.alias,
        &ks.relays,
        &ks.servers,
    )?;

    // §3.3 step 4 artifacts: retained = post-ban roster + THE OWNER (GitLab
    // !14 — the owner identity is never in the roster, and excluding it made
    // post-crash owner recovery via fold impossible).
    let owner_pk = hosting.public_key();
    let owner_hex = owner_pk.to_hex();
    let retained: Vec<(nostr::PublicKey, Role)> = new_roster
        .iter()
        .filter(|e| e.npub != owner_hex)
        .map(|e| {
            nostr::PublicKey::from_hex(&e.npub)
                .map(|pk| (pk, e.role))
                .map_err(|err| anyhow!("roster entry {} is not a valid pubkey: {err}", e.npub))
        })
        .chain(std::iter::once(Ok((owner_pk, Role::Write))))
        .collect::<Result<_>>()?;

    let state_payload = serde_json::to_vec(&rekey::StateSlot {
        community_root: hex::encode(new_root),
        state_key: hex::encode(new_state_key),
        epoch: new_epoch,
        roster: new_roster.clone(),
        banned: new_banned.clone(),
    })?;
    let collab_payload = serde_json::to_vec(&rekey::CollabSlot {
        collab_key: hex::encode(new_collab_key),
        epoch: new_epoch,
    })?;
    let write_payload = serde_json::to_vec(&rekey::WriteSlot {
        write_secret: hex::encode(new_write_secret),
        epoch: new_epoch,
    })?;
    let state_slots: Vec<(nostr::PublicKey, Vec<u8>)> = retained
        .iter()
        .map(|(pk, _)| (*pk, state_payload.clone()))
        .collect();
    let collab_slots: Vec<(nostr::PublicKey, Vec<u8>)> = retained
        .iter()
        .map(|(pk, _)| (*pk, collab_payload.clone()))
        .collect();
    // Write-scope slots go ONLY to push-role members (roster fold): a member
    // with no slot here concludes demoted/never-had, never "removed".
    let write_slots: Vec<(nostr::PublicKey, Vec<u8>)> = retained
        .iter()
        .filter(|(_, role)| *role == Role::Write)
        .map(|(pk, _)| (*pk, write_payload.clone()))
        .collect();

    let (state_wrap, state_raw) = rekey::build_rekey(
        &hosting,
        &community_id,
        &prior_root,
        Scope::State,
        new_epoch,
        &state_slots,
        None,
        &Scope::all(),
    )?;
    let (collab_wrap, collab_raw) = rekey::build_rekey(
        &hosting,
        &community_id,
        &prior_root,
        Scope::Collab,
        new_epoch,
        &collab_slots,
        None,
        &Scope::all(),
    )?;
    let prevcommit = rekey::write_scope_prevcommit(&old_write_secret, old_epoch);
    let (write_wrap, write_raw) = rekey::build_rekey(
        &hosting,
        &community_id,
        &prior_root,
        Scope::Write,
        new_epoch,
        &write_slots,
        Some(&prevcommit),
        &Scope::all(),
    )?;

    // §3.3 step 5: 30640″ — new-only sets (a template, rebuilt per relay at
    // publish time). Frees every old key server-side (including this epoch's
    // rekey addresses: their wraps are already stored and stay readable —
    // deregistration stops only NEW admissions).
    let narrow = events::build_registration_keysets(
        &hosting,
        &[&new_write_keys],
        &[&new_guestbook],
        &ks.alias,
        &ks.relays,
        &ks.servers,
    )?;

    // GitLab !14: persist EVERYTHING before publishing anything. From here a
    // crash + retry resumes byte-identically instead of forking the epoch.
    let pending = PendingEpoch {
        v: 1,
        kind: "revoke".to_string(),
        target: banned_hex,
        old_epoch,
        new_epoch,
        roster: new_roster,
        banned: new_banned,
        community_root: Some(hex::encode(new_root)),
        state_key: Some(hex::encode(new_state_key)),
        collab_key: Some(hex::encode(new_collab_key)),
        write_secret: hex::encode(new_write_secret),
        prior_root: Some(hex::encode(prior_root)),
        widen_json: widen.as_json(),
        narrow_json: narrow.as_json(),
        rekeys: [
            (Scope::State, &state_wrap, &state_raw),
            (Scope::Collab, &collab_wrap, &collab_raw),
            (Scope::Write, &write_wrap, &write_raw),
        ]
        .into_iter()
        .map(|(scope, wrap, raw)| PendingRekey {
            scope: scope.name().to_string(),
            wrap_json: wrap.as_json(),
            raw_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw),
        })
        .collect(),
    };
    save_pending(&pending, &community_id)?;
    run_pending_rotation(repo_dir, &ks, &pending)
}

/// `cord-git demote <npub>` — writer→reader. Plan §2/§4: a STANDALONE
/// write-scope rotation plus the 30640 w-set update — NO refounding (root and
/// channel keys stay; the demoted member keeps read access by design). Same
/// §3.3 widen→wait→artifact→narrow sequencing, restricted to the write scope.
/// GitLab !14: persisted before publish and resumable, exactly like revoke.
pub fn demote(repo_dir: &Path, npub: &str) -> Result<String> {
    let community_id = read_pointer(repo_dir)?;
    let ks = Keystore::load(&community_id)?;
    if !ks.is_owner() {
        bail!("only the repo owner (hosting-key holder) can demote");
    }
    if !ks.is_write() {
        bail!("owner keystore is missing the write secret");
    }
    let hosting = ks.hosting_keys()?;
    let member_pk =
        nostr::PublicKey::parse(npub).map_err(|e| anyhow!("invalid npub to demote: {e}"))?;
    let member_hex = member_pk.to_hex();
    freshness_guard(repo_dir, &ks)?;

    // GitLab !14: resume an interrupted identical rotation (Completed = a
    // stale adopted file, cleaned up by the gate — fall through, see revoke).
    match pending_gate(&ks, "demote", &member_hex)? {
        PendingGate::Resume(p) => return run_pending_rotation(repo_dir, &ks, &p),
        PendingGate::Completed | PendingGate::None => {}
    }
    // Mirror revoke's already-banned path (verify F4): if the target is
    // already a reader, the demote fully adopted and only the trailing
    // snapshot push can still be owed (crash between adoption/cleanup and
    // the push) — without it the repo's 30641 chain stays authored by the
    // freed old write key and every clone reads an EMPTY repo.
    match ks.roster.iter().find(|e| e.npub == member_hex) {
        None => bail!("npub is not in the roster"),
        Some(e) if e.role != Role::Write => {
            eprintln!(
                "{member_hex} is already a reader — the demote adopted; \
                 completing the snapshot push"
            );
            return push(repo_dir, true);
        }
        _ => {}
    }

    // Roster snapshot with the target flipped to read — applied to the
    // keystore only when the rotation adopts.
    let mut new_roster = ks.roster.clone();
    let entry = new_roster
        .iter_mut()
        .find(|e| e.npub == member_hex)
        .expect("roster membership checked above");
    entry.role = Role::Read;

    let prior_root = ks.community_root_bytes()?;
    let old_epoch = ks.epoch;
    let new_epoch = old_epoch.checked_add(1).context("epoch overflow")?;
    ensure_no_existing_rekeys(&ks, &hosting, new_epoch)?;
    let old_write_secret = ks
        .write_secret_bytes()?
        .context("owner keystore is missing the write secret")?;
    let old_write_keys = ks.write_keys()?;
    let guestbook = ks.guestbook_keys()?;

    let new_write_secret = crypto::random_32();
    let new_write_keys = crypto::derive_write_keys(&new_write_secret, new_epoch)?;
    // Root does not roll on demotion. Only THIS epoch's write-scope address
    // is registered, and only for the widen→narrow window (GitLab !13 — see
    // revoke for the cross-repo admission contract).
    let addr_write = rekey::rekey_address(&prior_root, &community_id, Scope::Write, new_epoch)?;

    // Widen/narrow are templates (rebuilt per relay at publish time) — see
    // revoke.
    let widen = events::build_registration_keysets(
        &hosting,
        &[&old_write_keys, &new_write_keys],
        &[&guestbook, &addr_write],
        &ks.alias,
        &ks.relays,
        &ks.servers,
    )?;

    let write_payload = serde_json::to_vec(&rekey::WriteSlot {
        write_secret: hex::encode(new_write_secret),
        epoch: new_epoch,
    })?;
    // Retained writers from the roster snapshot + the OWNER (GitLab !14 —
    // owner fold-recovery needs an owner slot here too).
    let owner_pk = hosting.public_key();
    let owner_hex = owner_pk.to_hex();
    let write_slots: Vec<(nostr::PublicKey, Vec<u8>)> = new_roster
        .iter()
        .filter(|e| e.role == Role::Write && e.npub != owner_hex)
        .map(|e| {
            nostr::PublicKey::from_hex(&e.npub)
                .map(|pk| (pk, write_payload.clone()))
                .map_err(|err| anyhow!("roster entry {} is not a valid pubkey: {err}", e.npub))
        })
        .chain(std::iter::once(Ok((owner_pk, write_payload.clone()))))
        .collect::<Result<_>>()?;
    let prevcommit = rekey::write_scope_prevcommit(&old_write_secret, old_epoch);
    let (write_wrap, write_raw) = rekey::build_rekey(
        &hosting,
        &community_id,
        &prior_root,
        Scope::Write,
        new_epoch,
        &write_slots,
        Some(&prevcommit),
        &[Scope::Write],
    )?;

    // Narrow strictly after the widen per relay at publish time (template).
    let narrow = events::build_registration_keysets(
        &hosting,
        &[&new_write_keys],
        &[&guestbook],
        &ks.alias,
        &ks.relays,
        &ks.servers,
    )?;
    let pending = PendingEpoch {
        v: 1,
        kind: "demote".to_string(),
        target: member_hex,
        old_epoch,
        new_epoch,
        roster: new_roster,
        banned: ks.banned.clone(),
        community_root: None,
        state_key: None,
        collab_key: None,
        write_secret: hex::encode(new_write_secret),
        prior_root: Some(hex::encode(prior_root)),
        widen_json: widen.as_json(),
        narrow_json: narrow.as_json(),
        rekeys: vec![PendingRekey {
            scope: Scope::Write.name().to_string(),
            wrap_json: write_wrap.as_json(),
            raw_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &write_raw,
            ),
        }],
    };
    save_pending(&pending, &community_id)?;
    run_pending_rotation(repo_dir, &ks, &pending)
}

/// `cord-git promote <npub>` — reader→writer. Plan §2/§4: Grant (roster) +
/// `write_secret` delivery as a 3313-style whisper to the member's OWN inbox
/// relay (same leak rule as invites: never the git node). No rotation — the
/// shared write key is already registered.
pub fn promote(
    repo_dir: &Path,
    npub: &str,
    via_relay: &str,
    out_file: Option<&Path>,
) -> Result<String> {
    let community_id = read_pointer(repo_dir)?;
    let mut ks = Keystore::load(&community_id)?;
    if !ks.is_owner() {
        bail!("only the repo owner (hosting-key holder) can promote");
    }
    if !ks.is_write() {
        bail!("owner keystore is missing the write secret");
    }
    if load_pending(&community_id)?.is_some() {
        bail!(
            "an interrupted rotation is still pending — complete it first \
             (rerun the revoke/demote command); a grant now would be rolled \
             back when the pending rotation adopts its roster snapshot"
        );
    }
    let via_norm = normalize_relay_url(via_relay);
    if ks.relays.iter().any(|r| normalize_relay_url(r) == via_norm) {
        bail!(
            "refusing to deliver a promotion to a git node ({via_relay}) — \
             use the member's own inbox relay"
        );
    }
    let member_pk =
        nostr::PublicKey::parse(npub).map_err(|e| anyhow!("invalid npub to promote: {e}"))?;
    let member_hex = member_pk.to_hex();

    // Grant: upsert the roster entry to the push role.
    ks.roster.retain(|e| e.npub != member_hex);
    ks.roster.push(RosterEntry {
        npub: member_hex.clone(),
        role: Role::Write,
        granted_at: now_secs(),
    });

    let (wrap, _bundle) = invite::wrap_promotion(&ks, &member_pk)?;
    let out = relay::publish(via_relay, &wrap)?;
    if !out.accepted {
        bail!("inbox relay rejected the promotion: {}", out.message);
    }
    let stored = relay::event_by_id(via_relay, &wrap.id.to_hex())?;
    if !stored.iter().any(|e| e.id == wrap.id) {
        bail!("promotion was accepted but is not served back by the inbox relay");
    }
    ks.save()?;
    if let Some(path) = out_file {
        crate::keystore::write_0600(path, wrap.as_json().as_bytes())?;
    }
    Ok(wrap.id.to_hex())
}

/// `cord-git promote-accept` — member side of a promotion. The delivered
/// secret is trusted ONLY after it derives a write key listed in the live
/// 30640, verified against the tenant pubkey from the EXISTING keystore
/// (never from the whisper): a forged promotion cannot smuggle a bad secret.
pub fn promote_accept(member_keys: &nostr::Keys, source: InviteSource) -> Result<String> {
    let bundle = match source {
        InviteSource::Relay(url) => {
            let me = member_keys.public_key().to_hex();
            let wraps = relay::giftwraps_for(&url, &me)?;
            let mut last_err: Option<anyhow::Error> = None;
            let mut found = None;
            for wrap in &wraps {
                match invite::unwrap_promotion(member_keys, wrap) {
                    Ok(b) => {
                        found = Some(b);
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            found.ok_or_else(|| match last_err {
                Some(e) => anyhow!("no usable promotion on {url} for this key (last error: {e})"),
                None => anyhow!("no promotion wraps addressed to this key on {url}"),
            })?
        }
        InviteSource::File(path) => {
            let json = std::fs::read_to_string(&path)
                .with_context(|| format!("cannot read promotion file {path:?}"))?;
            let wrap = nostr::Event::from_json(&json)
                .map_err(|e| anyhow!("promotion file is not an event: {e}"))?;
            invite::unwrap_promotion(member_keys, &wrap)?
        }
        InviteSource::Stdin => {
            let mut json = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut json)?;
            let wrap = nostr::Event::from_json(json.trim())
                .map_err(|e| anyhow!("stdin is not a promotion event: {e}"))?;
            invite::unwrap_promotion(member_keys, &wrap)?
        }
    };

    let mut ks = Keystore::load(&bundle.community_id)
        .context("no keystore for the promoted community — join from an invite first")?;
    if bundle.epoch != ks.epoch {
        bail!(
            "promotion is for epoch {} but this keystore is at epoch {} — \
             run `cord-git fold` first, then ask for a fresh promotion if needed",
            bundle.epoch,
            ks.epoch
        );
    }
    let secret = hex32(&bundle.write_secret)?;
    let wk = crypto::derive_write_keys(&secret, bundle.epoch)?;
    let w_keys = live_w_keys(&ks)?;
    if !w_keys.contains(&wk.public_key().to_hex()) {
        bail!(
            "promotion secret does not derive a registered write key — \
             stale or forged; ask for a fresh promotion"
        );
    }
    ks.write_secret = Some(bundle.write_secret);
    ks.role = Role::Write;
    ks.save()?;
    Ok(ks.community_id.clone())
}

/// The fold decision for one epoch — a pure function of the genuine rekeys
/// observed, unit-testable without a relay (GitLab !12/!14).
enum EpochPlan {
    /// Complete, consistent epoch: apply these (scope → my slot) conclusions.
    Apply(Vec<(Scope, Option<Vec<u8>>)>),
    /// Some scopes the epoch requires are not visible — refuse to apply a
    /// partial epoch (withheld scope, or folding inside the owner's
    /// sequential publish window). Nothing is applied; retry later.
    Incomplete { missing: Vec<Scope> },
    /// The observed genuine rekeys contradict each other — the epoch is
    /// forked (two genuine rekey sets). Never silently pick a side.
    Fork(String),
}

/// Decide one epoch's fold from the genuine (fully verified) rekeys observed
/// at its addresses. Rules (NORMATIVE, GitLab !12):
/// - every genuine rekey carries the tenant-signed `scopes` set; all genuine
///   rekeys of the epoch MUST agree on it exactly, else the epoch is forked;
/// - two genuine rekeys for the SAME scope carrying DIFFERENT slot payloads
///   for this member = forked epoch (loud fatal, GitLab !14);
/// - every scope in the agreed set must be observed, else Incomplete — a
///   demote epoch's set is write-only BY DESIGN, so this never confuses a
///   standalone write-scope rotation with a partially withheld refounding.
fn plan_epoch(genuine: &[(Scope, &rekey::ParsedRekey)]) -> EpochPlan {
    // Every genuine rekey of the epoch must carry the SAME tenant-signed
    // scope set — any disagreement means the epoch is forked.
    let mut required: Option<Vec<Scope>> = None;
    for (_, p) in genuine {
        let mut sorted = p.epoch_scopes.clone();
        sorted.sort();
        match &required {
            None => required = Some(sorted),
            Some(req) if *req == sorted => {}
            Some(_) => {
                return EpochPlan::Fork(
                    "genuine rekeys of one epoch disagree on the epoch's scope set — \
                     the epoch is forked; do NOT apply anything, contact the owner out-of-band"
                        .to_string(),
                );
            }
        }
    }
    let Some(required) = required else {
        // No genuine rekeys at all: caller treats as "no such epoch".
        return EpochPlan::Apply(Vec::new());
    };
    // Two genuine rekeys for the SAME scope must carry the same slot for
    // this member — otherwise the epoch has two genuine rekey sets (!14).
    let mut conclusions: Vec<(Scope, Option<Vec<u8>>)> = Vec::new();
    for scope in Scope::all() {
        let mut per_scope = genuine.iter().filter(|(s, _)| *s == scope).map(|(_, p)| *p);
        let Some(first) = per_scope.next() else { continue };
        for other in per_scope {
            if other.slot != first.slot {
                return EpochPlan::Fork(format!(
                    "two genuine tenant-signed {}-scope rekeys at the same epoch carry different \
                     slots for this identity — the epoch is forked (aborted-rotation retry?); \
                     do NOT apply either, contact the owner out-of-band",
                    scope.name()
                ));
            }
        }
        conclusions.push((scope, first.slot.clone()));
    }
    let missing: Vec<Scope> = required
        .iter()
        .copied()
        .filter(|s| !conclusions.iter().any(|(c, _)| c == s))
        .collect();
    if !missing.is_empty() {
        return EpochPlan::Incomplete { missing };
    }
    conclusions.sort_by_key(|(s, _)| *s);
    EpochPlan::Apply(conclusions)
}

/// `cord-git fold` — member-side rotation fold. Walks epoch-by-epoch from the
/// member's current (root, epoch): derives the per-scope rekey addresses,
/// fetches + verifies the rekeys (tenant-signed only) from ALL configured
/// relays, and applies the epoch ATOMICALLY (GitLab !12): the tenant-signed
/// `scopes` set of each genuine rekey defines exactly which scopes the epoch
/// rotates, and the fold refuses to apply ANYTHING until every required scope
/// is observed and verified — a withheld scope (or folding inside the owner's
/// sequential publish window) aborts the fold instead of desyncing the member
/// forever. A demote epoch declares a write-only scope set by design.
///
/// Roster-fold conclusions (NORMATIVE): a write-scope rekey WITHOUT a slot
/// for this member = demoted or never-had-push (drop the secret, keep
/// reading); a state-scope rekey without a slot = excluded by the refounding
/// (revoked) — the keystore is left untouched and the fold errors out.
///
/// The keystore is saved ONCE at the end: a fold that errors out leaves the
/// on-disk keystore exactly as it was (retry-safe).
///
/// Returns the number of epochs applied.
pub fn fold(community_id: &str, member_keys: &nostr::Keys) -> Result<u32> {
    let mut ks = Keystore::load(community_id)?;
    let tenant_hex = ks.tenant_hex()?;
    let me = member_keys.public_key().to_hex();
    let mut applied = 0u32;
    loop {
        let root = ks.community_root_bytes()?;
        let next = match ks.epoch.checked_add(1) {
            Some(n) => n,
            None => break,
        };
        let prior_secret = ks.write_secret_bytes()?;
        let prior_write = prior_secret.as_ref().map(|s| (s, ks.epoch));

        // Gather every genuine rekey of this epoch: all three scope
        // addresses, ALL configured relays (a withholding relay must not be
        // able to hide a scope — GitLab !12/!13), paginated past any junk.
        let mut genuine: Vec<(Scope, rekey::ParsedRekey)> = Vec::new();
        for scope in Scope::all() {
            let addr = rekey::rekey_address(&root, &ks.community_id, scope, next)?;
            let filter = serde_json::json!({
                "kinds": [rekey::KIND_WRAP],
                "authors": [addr.public_key().to_hex()],
            });
            let wraps = relay::fetch_all_multi(&ks.relays, filter)?;
            for wrap in &wraps {
                // Forged/malformed wraps at the address are skipped; only a
                // fully-verified (tenant-signed, bound, epoch-exact) rekey
                // counts as observed.
                if let Ok(p) = rekey::parse_rekey(
                    wrap,
                    &ks.community_id,
                    &tenant_hex,
                    &root,
                    scope,
                    next,
                    member_keys,
                    prior_write,
                ) {
                    genuine.push((scope, p));
                }
            }
        }
        if genuine.is_empty() {
            break; // fully folded
        }
        let refs: Vec<(Scope, &rekey::ParsedRekey)> =
            genuine.iter().map(|(s, p)| (*s, p)).collect();
        let conclusions = match plan_epoch(&refs) {
            EpochPlan::Apply(c) if c.is_empty() => break,
            EpochPlan::Apply(c) => c,
            EpochPlan::Incomplete { missing } => {
                bail!(
                    "epoch {next} rekey set is incomplete (missing: {}) — refusing to apply a \
                     partial epoch (withheld scope or mid-publish window); retry later, and if \
                     it persists, point your keystore at another node",
                    missing
                        .iter()
                        .map(|s| s.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            EpochPlan::Fork(why) => {
                bail!("refusing to fold epoch {next}: {why}");
            }
        };

        for (scope, slot) in conclusions {
            match scope {
                Scope::State => {
                    let Some(bytes) = slot else {
                        bail!(
                            "epoch {next} refounding carries no slot for this identity — \
                             you have been excluded (revoked) from this community"
                        );
                    };
                    let slot: rekey::StateSlot = serde_json::from_slice(&bytes)
                        .context("state slot payload is not valid")?;
                    slot.validate()?;
                    if slot.epoch != next {
                        bail!("state slot epoch mismatch");
                    }
                    ks.community_root = Some(slot.community_root);
                    ks.state_key = slot.state_key;
                    ks.roster = slot.roster;
                    ks.banned = slot.banned;
                    // Role from the roster fold (may be overridden below by
                    // the write-scope conclusion). The owner identity is
                    // never in the roster: ownership is hosting-key
                    // possession, so the owner keeps the push role.
                    let is_owner_self = ks.is_owner() && me == tenant_hex;
                    ks.role = ks
                        .roster
                        .iter()
                        .find(|e| e.npub == me)
                        .map(|e| e.role)
                        .unwrap_or(if is_owner_self { Role::Write } else { Role::Read });
                }
                Scope::Collab => {
                    let Some(bytes) = slot else {
                        bail!(
                            "epoch {next} refounding retains this identity in the state scope \
                             but carries no collab slot — malformed rekey set, refusing to fold"
                        );
                    };
                    let slot: rekey::CollabSlot = serde_json::from_slice(&bytes)
                        .context("collab slot payload is not valid")?;
                    slot.validate()?;
                    if slot.epoch != next {
                        bail!("collab slot epoch mismatch");
                    }
                    ks.collab_key = slot.collab_key;
                }
                Scope::Write => match slot {
                    Some(bytes) => {
                        let slot: rekey::WriteSlot = serde_json::from_slice(&bytes)
                            .context("write slot payload is not valid")?;
                        slot.validate()?;
                        if slot.epoch != next {
                            bail!("write slot epoch mismatch");
                        }
                        ks.write_secret = Some(slot.write_secret);
                        ks.role = Role::Write;
                    }
                    None => {
                        // Roster-fold rule: no write-scope slot = demoted or
                        // never-had-push — NOT removal. Keep reading. (The
                        // owner always carries a write slot; its absence here
                        // means a forked/malformed epoch.)
                        if ks.is_owner() && me == tenant_hex {
                            bail!(
                                "epoch {next} write-scope rekey carries no slot for the OWNER \
                                 identity — forked or malformed epoch, refusing to fold"
                            );
                        }
                        ks.write_secret = None;
                        ks.role = Role::Read;
                    }
                },
            }
        }
        ks.epoch = next;
        // The rotation moved the repo to a fresh write coordinate — the old
        // CAS anchor can never match again.
        ks.manifest_prev = None;
        applied += 1;
    }
    // GitLab !14 backstop: bind the post-fold secrets to the live 30640
    // across ALL relays before declaring success — including when NOTHING
    // was applied: a member whose relays withhold every rekey must get a
    // loud desync error, not "already up to date" with deregistered keys.
    cross_check_live_registration(&ks)?;
    if applied > 0 {
        ks.save()?;
    }
    Ok(applied)
}

/// GitLab !14 cross-check (the `promote_accept` pattern, applied to fold):
/// the keystore's derived write key must be in the live 30640's w-set and
/// its guestbook key in the aux set — checked against the newest valid
/// registration served by ANY configured relay. A folded epoch whose keys
/// do not match the live registration is a fork branch; a fully withheld
/// rotation is a desync. Both are loud-fatal, never silently "up to date".
fn cross_check_live_registration(ks: &Keystore) -> Result<()> {
    let Some(live) = live_registration(ks)? else {
        bail!("no valid live registration (30640) found for this alias");
    };
    registration_matches_ks(ks, &live)
}

/// The pure check behind [`cross_check_live_registration`] (unit-testable).
fn registration_matches_ks(ks: &Keystore, live: &nostr::Event) -> Result<()> {
    if let Some(secret) = ks.write_secret_bytes()? {
        let wk = crypto::derive_write_keys(&secret, ks.epoch)?;
        if !parse_w_keys(live).contains(&wk.public_key().to_hex()) {
            bail!(
                "keystore and live registration disagree: your write key (epoch {}) is not in \
                 the live 30640 w-set — the repo rotated past what your relays showed you \
                 (withheld rekeys) or you were rotated out; retry from another node, or \
                 rejoin from a fresh invite",
                ks.epoch
            );
        }
    }
    let gb = ks.guestbook_keys()?;
    if !parse_aux_keys(live).contains(&gb.public_key().to_hex()) {
        bail!(
            "keystore and live registration disagree: your guestbook/stream key (epoch {}) is \
             not in the live 30640 aux set — the repo rotated past what your relays showed you \
             (withheld rekeys) or you were rotated out; retry from another node, or rejoin \
             from a fresh invite",
            ks.epoch
        );
    }
    Ok(())
}

/// `cord-git clone` — fetch latest 30641, decrypt the manifest + packs, and
/// materialize the repo at `dest`. Requires a local keystore for `community_id`
/// (from `create` on this machine or `join` from an invite).
pub fn clone(community_id: &str, dest: &Path) -> Result<()> {
    let mut ks = Keystore::load(community_id)
        .with_context(|| format!("no keystore for {community_id}; join or create first"))?;
    let server_url = ks.servers.first().context("no blob server configured")?.clone();
    let state_key = ks.state_key_bytes()?;

    // Refuse to clone into a non-empty directory: unpacking into an existing
    // tree could clobber files or execute pre-existing git hooks.
    if dest.exists() && dest.read_dir()?.next().is_some() {
        bail!("destination {dest:?} is not empty — refusing to clone into it");
    }
    git::init(dest)?;

    let Some(state) = latest_valid_state_root(&ks)? else {
        // Empty repo (registered but never pushed).
        write_pointer(dest, community_id)?;
        return Ok(());
    };

    // Read the manifest blob hash from the 30641 `m` tag.
    let m_hash = tag_value(&state, "m").ok_or_else(|| anyhow!("30641 missing m tag"))?;
    let man_wire = blob::get(&server_url, &m_hash)?;
    // Integrity: the operator must serve exactly the addressed ciphertext.
    if crypto::sha256_hex(&man_wire) != m_hash {
        bail!("manifest blob hash mismatch — operator served wrong bytes");
    }
    let man_json = crypto::decrypt_manifest(&state_key, &man_wire)?;
    let manifest = Manifest::from_json(&man_json)?;

    // Fetch + decrypt + unpack every pack.
    for pe in &manifest.packs {
        let wire = blob::get(&server_url, &pe.blob_id)?;
        if crypto::sha256_hex(&wire) != pe.blob_id {
            bail!("pack blob {} hash mismatch — operator served wrong bytes", pe.blob_id);
        }
        let key = hex32(&pe.key)?;
        let pack = crypto::decrypt_blob(&key, &wire)?;
        git::unpack(dest, &pack)?;
    }

    // Set refs + HEAD, then materialize the working tree. Validate every
    // refname/oid from the (write-member-authored) manifest before handing it
    // to the shelled-out git — a value starting with '-' or not matching the
    // expected shape could otherwise inject git flags.
    for (refname, oid) in &manifest.refs {
        if !is_safe_refname(refname) {
            bail!("manifest contains an unsafe refname: {refname:?}");
        }
        if !is_hex_oid(oid) {
            bail!("manifest contains an unsafe object id: {oid:?}");
        }
        git::update_ref(dest, refname, oid)?;
    }
    let head = pick_head(&manifest);
    if let Some(head_ref) = head {
        git::set_head(dest, &head_ref)?;
        let _ = git::checkout_head(dest);
    }

    write_pointer(dest, community_id)?;
    ks.manifest_prev = Some(state.id.to_hex());
    ks.save()?;
    Ok(())
}

/// A refname is safe iff it starts with `refs/` and contains only a
/// conservative character set (no leading dash, no whitespace/control, no `..`).
fn is_safe_refname(name: &str) -> bool {
    name.starts_with("refs/")
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.'))
}

/// A git object id is 40 (sha1) or 64 (sha256) lowercase/uppercase hex chars.
fn is_hex_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Prefer refs/heads/main|master, else the first branch.
fn pick_head(manifest: &Manifest) -> Option<String> {
    for pref in ["refs/heads/main", "refs/heads/master"] {
        if manifest.refs.contains_key(pref) {
            return Some(pref.to_string());
        }
    }
    manifest.refs.keys().next().cloned()
}

fn tag_value(event: &nostr::Event, name: &str) -> Option<String> {
    event.tags.iter().find_map(|t| {
        let v = t.clone().to_vec();
        if v.len() >= 2 && v[0] == name {
            Some(v[1].clone())
        } else {
            None
        }
    })
}

fn write_pointer(repo_dir: &Path, community_id: &str) -> Result<()> {
    std::fs::create_dir_all(repo_dir)?;
    std::fs::write(repo_dir.join(POINTER_FILE), community_id)?;
    Ok(())
}

fn read_pointer(repo_dir: &Path) -> Result<String> {
    let p = repo_dir.join(POINTER_FILE);
    let s = std::fs::read_to_string(&p)
        .with_context(|| format!("no {POINTER_FILE} in {repo_dir:?}; run `cord-git create` here"))?;
    Ok(s.trim().to_string())
}

fn hex32(h: &str) -> Result<[u8; 32]> {
    let v = hex::decode(h).map_err(|_| anyhow!("bad hex key"))?;
    v.as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 32-byte key"))
}

/// Verify JSON round-trips (used by `doctor`, cheap self-check).
pub fn event_json_ok(event: &nostr::Event) -> bool {
    nostr::Event::from_json(event.as_json()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::build_registration;
    use nostr::prelude::FinalizeEvent;
    use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};

    fn reg_for(tenant: &Keys, w: &Keys, alias: &str) -> nostr::Event {
        build_registration(
            tenant,
            w,
            &[],
            alias,
            &["ws://127.0.0.1:1".into()],
            &["http://127.0.0.1:1".into()],
        )
        .unwrap()
    }

    /// A kind-30641 signed by `signer` at a chosen created_at (d tag only —
    /// selection logic only inspects author/signature/created_at).
    fn sr_raw(signer: &Keys, alias: &str, at: u64) -> nostr::Event {
        EventBuilder::new(Kind::Custom(30641), "")
            .tags(vec![Tag::identifier(alias.to_string())])
            .custom_created_at(Timestamp::from_secs(at))
            .finalize(signer)
            .unwrap()
    }

    #[test]
    fn forged_signature_is_excluded() {
        let now = now_secs();
        let w = Keys::generate();
        let alias = "cd".repeat(16);
        let good = sr_raw(&w, &alias, now - 10);
        // Valid signature but from a key that is NOT in the w-set.
        let attacker = Keys::generate();
        let forged = sr_raw(&attacker, &alias, now - 5); // newer, must still lose
        let w_keys = vec![w.public_key().to_hex()];
        let selected = select_valid_state_root(vec![good.clone(), forged], &w_keys, now).unwrap();
        assert_eq!(selected.id, good.id);
    }

    #[test]
    fn future_dated_by_registered_key_is_excluded() {
        let now = now_secs();
        let w = Keys::generate();
        let alias = "cd".repeat(16);
        let good = sr_raw(&w, &alias, now - 10);
        // Same author (the real write key), but future-dated — the pinning attack.
        let pinned = sr_raw(&w, &alias, now + 100 * 365 * 24 * 3600);
        let w_keys = vec![w.public_key().to_hex()];
        let selected = select_valid_state_root(vec![good.clone(), pinned], &w_keys, now).unwrap();
        assert_eq!(selected.id, good.id);
        // Slight future within slack is fine.
        let ok = sr_raw(&w, &alias, now + 60);
        let selected = select_valid_state_root(vec![ok.clone()], &w_keys, now).unwrap();
        assert_eq!(selected.id, ok.id);
    }

    #[test]
    fn rotation_locks_out_old_key_events() {
        let now = now_secs();
        let old_w = Keys::generate();
        let new_w = Keys::generate();
        let alias = "cd".repeat(16);
        // Old key published (even recently); rotation lists only new_w.
        let old_state = sr_raw(&old_w, &alias, now - 5);
        let new_state = sr_raw(&new_w, &alias, now - 60); // older than old_state
        let new_w_keys = vec![new_w.public_key().to_hex()];
        let selected =
            select_valid_state_root(vec![old_state, new_state.clone()], &new_w_keys, now).unwrap();
        // Even though old_state is NEWER, its author is no longer registered.
        assert_eq!(selected.id, new_state.id);
    }

    #[test]
    fn tampered_event_fails_verify() {
        let now = now_secs();
        let w = Keys::generate();
        let alias = "cd".repeat(16);
        let mut ev = sr_raw(&w, &alias, now - 10);
        ev.content = "tampered".into(); // breaks the id/signature binding
        let w_keys = vec![w.public_key().to_hex()];
        assert!(select_valid_state_root(vec![ev], &w_keys, now).is_none());
    }

    #[test]
    fn registration_validity_rules() {
        let now = now_secs();
        let tenant = Keys::generate();
        let w = Keys::generate();
        let alias = "cd".repeat(16);
        let reg = reg_for(&tenant, &w, &alias);
        assert!(registration_is_valid(&reg, &tenant.public_key().to_hex(), now));
        // Wrong tenant (operator injecting a forged registration).
        let other = Keys::generate();
        let forged = reg_for(&other, &w, &alias);
        assert!(!registration_is_valid(&forged, &tenant.public_key().to_hex(), now));
        // W keys parse out.
        let keys = parse_w_keys(&reg);
        assert_eq!(keys, vec![w.public_key().to_hex()]);
        // A state root signed by w validates against the parsed set.
        let state = sr_raw(&w, &alias, now - 1);
        assert!(state_root_is_valid(&state, &keys, now));
    }

    #[test]
    fn aux_key_cannot_author_state_roots_client_side() {
        // A read-only member can derive the guestbook (aux) key from #collab —
        // its 30641s/pointer rumors must never be selected by other members.
        let now = now_secs();
        let tenant = Keys::generate();
        let w = Keys::generate();
        let aux = Keys::generate();
        let alias = "cd".repeat(16);
        let reg = build_registration(
            &tenant,
            &w,
            &[&aux],
            &alias,
            &["ws://127.0.0.1:1".into()],
            &["http://127.0.0.1:1".into()],
        )
        .unwrap();
        let w_keys = parse_w_keys(&reg);
        assert!(parse_aux_keys(&reg).contains(&aux.public_key().to_hex()));
        assert!(!w_keys.contains(&aux.public_key().to_hex()));
        let aux_state = sr_raw(&aux, &alias, now - 1);
        assert!(select_valid_state_root(vec![aux_state], &w_keys, now).is_none());
    }

    #[test]
    fn community_id_path_validation() {
        assert!(Keystore::load("../etc/passwd").is_err());
        assert!(Keystore::load("not-hex").is_err());
        assert!(Keystore::load(&"AB".repeat(32)).is_err()); // uppercase
    }

    // ---- epoch-atomic fold planning (GitLab !12/!14) ----

    fn rk(scope: Scope, scopes: &[Scope], slot: Option<Vec<u8>>) -> rekey::ParsedRekey {
        rekey::ParsedRekey {
            scope,
            epoch: 1,
            epoch_scopes: scopes.to_vec(),
            slot,
        }
    }

    #[test]
    fn plan_epoch_complete_refounding_applies_all_scopes() {
        let state = rk(Scope::State, &Scope::all(), Some(b"s".to_vec()));
        let collab = rk(Scope::Collab, &Scope::all(), Some(b"c".to_vec()));
        let write = rk(Scope::Write, &Scope::all(), Some(b"w".to_vec()));
        let genuine = [
            (Scope::State, &state),
            (Scope::Collab, &collab),
            (Scope::Write, &write),
        ];
        match plan_epoch(&genuine) {
            EpochPlan::Apply(c) => assert_eq!(c.len(), 3),
            _ => panic!("complete refounding epoch must apply"),
        }
    }

    #[test]
    fn plan_epoch_demote_is_write_only_by_design() {
        // A demote epoch declares a write-only scope set; state/collab rekeys
        // do not exist and are NOT "missing".
        let write = rk(Scope::Write, &[Scope::Write], Some(b"w".to_vec()));
        let genuine = [(Scope::Write, &write)];
        match plan_epoch(&genuine) {
            EpochPlan::Apply(c) => {
                assert_eq!(c.len(), 1);
                assert_eq!(c[0].0, Scope::Write);
            }
            _ => panic!("demote epoch must apply write-only"),
        }
    }

    #[test]
    fn plan_epoch_partial_refounding_is_incomplete_not_partial_apply() {
        // The !12 attack: state+collab visible, write withheld (or the fold
        // ran inside the owner's sequential publish window). Must NOT apply.
        let state = rk(Scope::State, &Scope::all(), Some(b"s".to_vec()));
        let collab = rk(Scope::Collab, &Scope::all(), Some(b"c".to_vec()));
        let genuine = [(Scope::State, &state), (Scope::Collab, &collab)];
        match plan_epoch(&genuine) {
            EpochPlan::Incomplete { missing } => assert_eq!(missing, vec![Scope::Write]),
            _ => panic!("partial refounding must be Incomplete"),
        }
        // Same for any other single-scope or two-scope subset.
        let write = rk(Scope::Write, &Scope::all(), Some(b"w".to_vec()));
        let genuine = [(Scope::Write, &write)];
        assert!(matches!(
            plan_epoch(&genuine),
            EpochPlan::Incomplete { .. }
        ));
    }

    #[test]
    fn plan_epoch_benign_duplicate_rekeys_apply() {
        // Same scope, same slot bytes (e.g. one wrap seen via two relays) —
        // not a fork.
        let a = rk(Scope::Write, &[Scope::Write], Some(b"w".to_vec()));
        let b = rk(Scope::Write, &[Scope::Write], Some(b"w".to_vec()));
        let genuine = [(Scope::Write, &a), (Scope::Write, &b)];
        assert!(matches!(plan_epoch(&genuine), EpochPlan::Apply(_)));
        // Some+None for the same scope is a contradiction.
        let c = rk(Scope::Write, &[Scope::Write], None);
        let genuine = [(Scope::Write, &a), (Scope::Write, &c)];
        assert!(matches!(plan_epoch(&genuine), EpochPlan::Fork(_)));
        // Same slot but disagreeing scope sets is a fork too.
        let d = rk(Scope::Write, &Scope::all(), Some(b"w".to_vec()));
        let genuine = [(Scope::Write, &a), (Scope::Write, &d)];
        assert!(matches!(plan_epoch(&genuine), EpochPlan::Fork(_)));
    }

    #[test]
    fn plan_epoch_two_genuine_different_slots_is_fork() {
        // GitLab !14: an aborted revoke retried with fresh secrets — two
        // genuine tenant-signed rekeys at one address, different payloads.
        let a = rk(Scope::State, &Scope::all(), Some(b"set-1".to_vec()));
        let b = rk(Scope::State, &Scope::all(), Some(b"set-2".to_vec()));
        let collab = rk(Scope::Collab, &Scope::all(), Some(b"c".to_vec()));
        let write = rk(Scope::Write, &Scope::all(), Some(b"w".to_vec()));
        let genuine = [
            (Scope::State, &a),
            (Scope::State, &b),
            (Scope::Collab, &collab),
            (Scope::Write, &write),
        ];
        match plan_epoch(&genuine) {
            EpochPlan::Fork(why) => assert!(why.contains("state")),
            _ => panic!("two genuine rekey sets must be a loud fork"),
        }
    }

    #[test]
    fn plan_epoch_scope_set_disagreement_is_fork() {
        // One rekey says the epoch is write-only, another says full
        // refounding — cannot both be the same epoch.
        let state = rk(Scope::State, &Scope::all(), Some(b"s".to_vec()));
        let write = rk(Scope::Write, &[Scope::Write], Some(b"w".to_vec()));
        let genuine = [(Scope::State, &state), (Scope::Write, &write)];
        assert!(matches!(plan_epoch(&genuine), EpochPlan::Fork(_)));
    }

    #[test]
    fn plan_epoch_empty_means_no_such_epoch() {
        assert!(matches!(plan_epoch(&[]), EpochPlan::Apply(c) if c.is_empty()));
    }

    // ---- fold cross-check (GitLab !14) ----

    fn test_keystore(epoch: u32) -> Keystore {
        Keystore {
            community_id: "ab".repeat(32),
            repo_name: "t".into(),
            hosting_nsec: None,
            tenant_pub: Some(Keys::generate().public_key().to_hex()),
            owner_salt: hex::encode([1u8; 32]),
            community_root: Some(hex::encode([2u8; 32])),
            state_key: hex::encode([3u8; 32]),
            collab_key: hex::encode([4u8; 32]),
            write_secret: Some(hex::encode([5u8; 32])),
            epoch,
            alias: "cd".repeat(16),
            relays: vec!["ws://127.0.0.1:1".into()],
            servers: vec!["http://127.0.0.1:1".into()],
            role: Role::Write,
            manifest_prev: None,
            roster: vec![],
            banned: vec![],
        }
    }

    #[test]
    fn cross_check_matches_and_mismatches() {
        let ks = test_keystore(3);
        let tenant = Keys::generate();
        let wk = ks.write_keys().unwrap();
        let gb = ks.guestbook_keys().unwrap();
        // Registration listing the keystore's keys → passes.
        let good = crate::events::build_registration_keysets(
            &tenant,
            &[&wk],
            &[&gb],
            &ks.alias,
            &ks.relays,
            &ks.servers,
        )
        .unwrap();
        registration_matches_ks(&ks, &good).unwrap();
        // A registration with a DIFFERENT write key → write-key mismatch.
        let other_w = Keys::generate();
        let bad_w = crate::events::build_registration_keysets(
            &tenant,
            &[&other_w],
            &[&gb],
            &ks.alias,
            &ks.relays,
            &ks.servers,
        )
        .unwrap();
        let e = registration_matches_ks(&ks, &bad_w).unwrap_err();
        assert!(format!("{e:#}").contains("w-set"), "{e:#}");
        // A registration with a different guestbook key → aux mismatch.
        let other_gb = Keys::generate();
        let bad_gb = crate::events::build_registration_keysets(
            &tenant,
            &[&wk],
            &[&other_gb],
            &ks.alias,
            &ks.relays,
            &ks.servers,
        )
        .unwrap();
        let e = registration_matches_ks(&ks, &bad_gb).unwrap_err();
        assert!(format!("{e:#}").contains("aux set"), "{e:#}");
        // Read-only keystore (no write secret): write check skipped, aux ok.
        let mut ro = test_keystore(3);
        ro.write_secret = None;
        registration_matches_ks(&ro, &good).unwrap();
    }

    // ---- pending-rotation gate (GitLab !14) ----

    /// Serial fs-backed gate tests (env-mutating; one test fn on purpose).
    #[test]
    fn pending_gate_paths() {
        let dir = std::env::temp_dir().join(format!("cord-git-gate-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Point CORD_GIT_HOME at the temp dir for the duration of the test
        // (restored at the end; other unit tests never touch the keystore fs).
        let prev_home = std::env::var("CORD_GIT_HOME").ok();
        std::env::set_var("CORD_GIT_HOME", &dir);
        let mut ks = test_keystore(4);
        ks.save().unwrap();
        let cid = ks.community_id.clone();
        let pending = PendingEpoch {
            v: 1,
            kind: "revoke".into(),
            target: "ee".repeat(32),
            old_epoch: 4,
            new_epoch: 5,
            roster: vec![],
            banned: vec![],
            community_root: Some(hex::encode([9u8; 32])),
            state_key: Some(hex::encode([8u8; 32])),
            collab_key: Some(hex::encode([7u8; 32])),
            write_secret: hex::encode([6u8; 32]),
            prior_root: Some(hex::encode([2u8; 32])),
            widen_json: "{}".into(),
            narrow_json: "{}".into(),
            rekeys: vec![],
        };

        // No pending file → None.
        assert!(matches!(pending_gate(&ks, "revoke", &"ee".repeat(32)).unwrap(), PendingGate::None));

        // Corrupt pending file → loud error, never a guess.
        std::fs::write(pending_path(&cid).unwrap(), b"not json").unwrap();
        assert!(load_pending(&cid).is_err());
        assert!(pending_gate(&ks, "revoke", &"ee".repeat(32)).is_err());

        // Epoch disagreement (keystore moved past the pending file) → bail.
        save_pending(&pending, &cid).unwrap();
        ks.epoch = 6;
        let e = pending_gate(&ks, "revoke", &"ee".repeat(32)).unwrap_err();
        assert!(format!("{e:#}").contains("disagree"), "{e:#}");
        ks.epoch = 4;

        // Kind/target mismatch → bail with guidance, file left in place.
        let e = pending_gate(&ks, "demote", &"ee".repeat(32)).unwrap_err();
        assert!(format!("{e:#}").contains("still pending"), "{e:#}");
        let e = pending_gate(&ks, "revoke", &"ff".repeat(32)).unwrap_err();
        assert!(format!("{e:#}").contains("still pending"), "{e:#}");
        assert!(pending_path(&cid).unwrap().exists());

        // Matching kind/target/epoch → Resume (no network needed on this path).
        assert!(matches!(
            pending_gate(&ks, "revoke", &"ee".repeat(32)).unwrap(),
            PendingGate::Resume(_)
        ));

        let _ = std::fs::remove_dir_all(&dir);
        match prev_home {
            Some(v) => std::env::set_var("CORD_GIT_HOME", v),
            None => std::env::remove_var("CORD_GIT_HOME"),
        }
    }

    // ---- registration template rebuild + key-set matching ----

    #[test]
    fn rebuild_registration_drops_aux_and_revalidates_pop() {
        let tenant = Keys::generate();
        let w = Keys::generate();
        let aux1 = Keys::generate();
        let aux2 = Keys::generate();
        let alias = "ab".repeat(16);
        let template = crate::events::build_registration_keysets(
            &tenant,
            &[&w],
            &[&aux1, &aux2],
            &alias,
            &["ws://127.0.0.1:1".into()],
            &["http://127.0.0.1:1".into()],
        )
        .unwrap();
        // Full rebuild: same tags, new created_at, valid signature.
        let rebuilt = rebuild_registration(&template.as_json(), &[], &tenant, 1_700_000_000).unwrap();
        rebuilt.verify().unwrap();
        assert_eq!(rebuilt.created_at.as_secs(), 1_700_000_000);
        assert!(registration_key_sets_match(&rebuilt, &template));
        // PoP tags survive verbatim (they bind tenant+alias, not created_at).
        assert!(crate::crypto::verify_key_pop(
            &w.public_key().to_hex(),
            rebuilt
                .tags
                .iter()
                .find_map(|t| {
                    let v = t.clone().to_vec();
                    if v.len() >= 3 && v[0] == "w" && v[1] == w.public_key().to_hex() {
                        Some(v[2].clone())
                    } else {
                        None
                    }
                })
                .as_deref()
                .unwrap(),
            &tenant.public_key().to_hex(),
            &alias
        ));
        // Dropping one aux key changes the aux set (and no longer matches).
        let minimal = rebuild_registration(
            &template.as_json(),
            &[aux2.public_key().to_hex()],
            &tenant,
            1_700_000_001,
        )
        .unwrap();
        minimal.verify().unwrap();
        assert!(!registration_key_sets_match(&minimal, &template));
        let aux_keys = parse_aux_keys(&minimal);
        assert!(aux_keys.contains(&aux1.public_key().to_hex()));
        assert!(!aux_keys.contains(&aux2.public_key().to_hex()));
        // A tampered template is rejected (signature no longer verifies).
        let mut bad = template.clone();
        bad.content = "tampered".into();
        assert!(rebuild_registration(&bad.as_json(), &[], &tenant, 1).is_err());
    }
}
