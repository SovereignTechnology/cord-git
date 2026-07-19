//! High-level create / push / clone orchestration tying crypto + keystore +
//! events + relay + blob + git together. See design §3, §4, §7.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};

use crate::crypto;
use crate::events::{self, BlobOp};
use crate::keystore::{Keystore, Role};
use crate::manifest::{Manifest, PackEntry};
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
    registration
        .tags
        .iter()
        .filter_map(|t| {
            let v = t.clone().to_vec();
            if v.len() >= 2 && v[0] == "w" {
                Some(v[1].clone())
            } else {
                None
            }
        })
        .collect()
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
    let mut regs = relay::registration_candidates(relay_url, &ks.alias)?;
    let now = now_secs();
    regs.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.to_hex().cmp(&b.id.to_hex()))
    });
    for reg in &regs {
        if registration_is_valid(reg, &tenant_hex, now) {
            return Ok(parse_w_keys(reg));
        }
    }
    bail!("no valid live registration (30640) found for this alias")
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
    let write_secret = crypto::random_32();
    let alias = hex::encode(crypto::random_32())[..32].to_string();
    let epoch = 0u32;
    let write_keys = crypto::derive_write_keys(&write_secret, epoch)?;

    let ks = Keystore {
        community_id: community_id.clone(),
        repo_name: name.to_string(),
        hosting_nsec: hosting.secret_key().to_secret_hex(),
        owner_salt: hex::encode(salt),
        state_key: hex::encode(state_key),
        collab_key: hex::encode(collab_key),
        write_secret: Some(hex::encode(write_secret)),
        epoch,
        alias: alias.clone(),
        relays: vec![node_relay.to_string()],
        servers: vec![node_server.to_string()],
        role: Role::Write,
        manifest_prev: None,
    };

    let reg = events::build_registration(
        &hosting,
        &write_keys,
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

    Ok(Created {
        url: format!("cord://{community_id}"),
        community_id,
        alias,
    })
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
    let relay_url = ks.relays.first().context("no relay configured")?.clone();
    let hosting = ks.hosting_keys()?;

    // Freshness guard: refuse to rotate when the LOCAL WORKING TREE's refs
    // differ from the remote manifest's refs. rotate re-publishes the local
    // checkout under new secrets, so rotating from a stale checkout would
    // silently roll back every reader. (Comparing refs, not the keystore
    // anchor — another clone may have moved the keystore past this checkout.)
    match remote_manifest(&ks)? {
        None => {} // never pushed — nothing to be behind
        Some(m) => {
            let local_refs = git::branch_refs(repo_dir)?;
            if m.refs != local_refs {
                bail!(
                    "refusing to rotate: this checkout's refs differ from the remote — \
                     re-clone (or fast-forward) first"
                );
            }
        }
    }

    let new_write_secret = crypto::random_32();
    let new_state_key = crypto::random_32();
    let new_write_keys = crypto::derive_write_keys(&new_write_secret, ks.epoch)?;

    // Re-register with the new write key only; the server frees the old key's
    // claim, so a 30641 signed by the old key is rejected thereafter.
    let reg = events::build_registration(
        &hosting,
        &new_write_keys,
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
    fn community_id_path_validation() {
        assert!(Keystore::load("../etc/passwd").is_err());
        assert!(Keystore::load("not-hex").is_err());
        assert!(Keystore::load(&"AB".repeat(32)).is_err()); // uppercase
    }
}
