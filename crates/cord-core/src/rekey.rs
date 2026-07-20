//! Rekey (kind-3303) machinery for revoke / demote / promote — plan §2
//! (revoke row), §3.3 (rotation sequencing) and §4 (lifecycle).
//!
//! A rekey is how retained members receive the post-rotation secrets:
//! - The `#state` and `#collab` channels each rekey at a pseudonymous
//!   per-scope, per-epoch address.
//! - The `write_secret` rotates via a PARALLEL SYNTHETIC WRITE SCOPE at its
//!   own DEDICATED address (plan §2 revoke row): sharing the channel base
//!   address would corrupt the removal test, so the write scope gets
//!   `scope_id = sha256("cord-git/write-scope-id/v1" ‖ 0x00 ‖ community_id)`
//!   — bound to the COMMUNITY id (stable across refoundings), NOT to any
//!   per-epoch namespace — and the address
//!   `group_key("concord/rekey-pseudonym", prior_root, write_scope_id,
//!   write_epoch+1)`. Its chain continuity is committed by a `prevcommit`
//!   over the PRIOR `(write_secret, write_epoch)` (A.5 shape).
//!
//! Wire shape (CORD-git-native, behind the KeyBackend seam — spec §7):
//! - inner rumor: kind 3303, SIGNED BY THE TENANT hosting key ("authority is
//!   rejection" — any member can derive the outer address key from the prior
//!   root, so authenticity comes only from this signature), tags
//!   `cgc`=community, `scope`=scope-id, `epoch`=new epoch, and (write scope)
//!   `prevcommit`; content = per-member slots.
//! - each slot: an opaque `hint` (only the member can recognize it — member
//!   npubs never appear on the git node) plus a NIP-44 ciphertext from a
//!   fresh ephemeral key to the member npub carrying the new secrets. A
//!   member with no slot in a write-scope rekey concludes demoted/never-had;
//!   no slot in a state-scope rekey concludes revoked (roster-fold rule).
//! - outer: 1059 wrap signed by the derived rekey-pseudonym key (which MUST
//!   already be in the live 30640's aux set — §3.3 sequencing), content
//!   sealed under a key derived from the prior root (operator-opaque).

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use nostr::nips::nip44;
use nostr::prelude::FinalizeEvent;
use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, SecretKey, Tag, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto;
use crate::keystore::{BanEntry, RosterEntry};

/// Concord rekey rumor kind.
pub const KIND_REKEY: u16 = 3303;
/// Outer wrap kind (same as every CORD stream event).
pub const KIND_WRAP: u16 = 1059;

/// The `group_key` derivation label for rekey addresses (Concord CORD-06
/// pseudonym family). NORMATIVE per plan §2 revoke row.
const REKEY_PSEUDONYM_LABEL: &[u8] = b"concord/rekey-pseudonym";
/// Scope-id labels. The write-scope label is NORMATIVE (plan §2 revoke row);
/// the channel labels mirror its shape.
const WRITE_SCOPE_LABEL: &[u8] = b"cord-git/write-scope-id/v1";
const STATE_SCOPE_LABEL: &[u8] = b"cord-git/state-scope-id/v1";
const COLLAB_SCOPE_LABEL: &[u8] = b"cord-git/collab-scope-id/v1";
/// Write-scope prevcommit domain (over the PRIOR (write_secret, epoch)).
const WRITE_SCOPE_PREVCOMMIT_LABEL: &[u8] = b"cord-git/write-scope-prevcommit/v1";
/// Envelope seal key label (outer wrap content; derived from the prior root).
const REKEY_SEAL_LABEL: &[u8] = b"cord-git/rekey-seal/v1";
/// Per-member slot hint label.
const REKEY_SLOT_LABEL: &[u8] = b"cord-git/rekey-slot/v1";

/// The three rekeyed scopes of one repo community.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// `#state` channel (manifest keys).
    State,
    /// `#collab` channel (guestbook/collab stream).
    Collab,
    /// The synthetic write scope carrying `write_secret` (dedicated address).
    Write,
}

impl Scope {
    pub fn name(self) -> &'static str {
        match self {
            Scope::State => "state",
            Scope::Collab => "collab",
            Scope::Write => "write",
        }
    }

    fn label(self) -> &'static [u8] {
        match self {
            Scope::State => STATE_SCOPE_LABEL,
            Scope::Collab => COLLAB_SCOPE_LABEL,
            Scope::Write => WRITE_SCOPE_LABEL,
        }
    }

    fn from_name(name: &str) -> Option<Scope> {
        match name {
            "state" => Some(Scope::State),
            "collab" => Some(Scope::Collab),
            "write" => Some(Scope::Write),
            _ => None,
        }
    }

    /// All scopes in canonical (declaration) order.
    pub fn all() -> [Scope; 3] {
        [Scope::State, Scope::Collab, Scope::Write]
    }
}

/// Render an epoch's expected scope set for the `scopes` tag: comma-joined
/// names in canonical order (deterministic wire bytes).
fn render_scope_set(scopes: &[Scope]) -> String {
    let mut sorted = scopes.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted
        .iter()
        .map(|s| s.name())
        .collect::<Vec<_>>()
        .join(",")
}

/// Parse a `scopes` tag value back into a scope set. Rejects unknown names
/// and duplicates — the tag is tenant-signed and must be exactly meaningful.
fn parse_scope_set(value: &str) -> Result<Vec<Scope>> {
    let mut scopes = Vec::new();
    for name in value.split(',') {
        let scope = Scope::from_name(name)
            .ok_or_else(|| anyhow!("scopes tag carries an unknown scope name {name:?}"))?;
        if scopes.contains(&scope) {
            bail!("scopes tag lists {} twice", scope.name());
        }
        scopes.push(scope);
    }
    if scopes.is_empty() {
        bail!("scopes tag is empty");
    }
    Ok(scopes)
}

fn community_id_bytes(community_id_hex: &str) -> Result<[u8; 32]> {
    if community_id_hex.len() != 64 {
        bail!("community id must be 64 hex chars");
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(community_id_hex, &mut out)
        .map_err(|_| anyhow!("community id is not valid hex"))?;
    Ok(out)
}

/// `scope_id = sha256(label ‖ 0x00 ‖ community_id)` where `community_id` is
/// the raw 32 bytes of the (hex-rendered) community id. Bound to the
/// community — NOT a per-refounding namespace — so the write-scope identity
/// is stable across refoundings (plan §2 revoke row).
pub fn scope_id(scope: Scope, community_id_hex: &str) -> Result<[u8; 32]> {
    let cid = community_id_bytes(community_id_hex)?;
    let mut h = Sha256::new();
    h.update(scope.label());
    h.update([0u8]);
    h.update(cid);
    Ok(h.finalize().into())
}

/// CORD-06-style `group_key`: derive the pseudonymous keypair for
/// (label, root, scope_id, epoch). `sk = HKDF-SHA256(salt=label, ikm=root,
/// info=scope_id ‖ epoch_le)`, rerolled into the valid scalar range.
pub fn group_key(label: &[u8], root: &[u8; 32], scope_id: &[u8; 32], epoch: u32) -> Result<Keys> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(label), root);
    let mut okm = [0u8; 32];
    let mut info = Vec::with_capacity(40);
    info.extend_from_slice(scope_id);
    info.extend_from_slice(&epoch.to_le_bytes());
    for attempt in 0u8..=255 {
        hk.expand(&info, &mut okm)
            .map_err(|_| anyhow!("hkdf expand"))?;
        if let Ok(sk) = SecretKey::from_slice(&okm) {
            return Ok(Keys::new(sk));
        }
        info.push(attempt);
    }
    Err(anyhow!("could not derive a valid group key"))
}

/// The rekey-pseudonym keypair (whose x-only pubkey is the "address") for one
/// scope at one epoch, from the PRIOR community root:
/// `group_key("concord/rekey-pseudonym", prior_root, scope_id, epoch)`.
pub fn rekey_address(
    prior_root: &[u8; 32],
    community_id_hex: &str,
    scope: Scope,
    epoch: u32,
) -> Result<Keys> {
    let sid = scope_id(scope, community_id_hex)?;
    group_key(REKEY_PSEUDONYM_LABEL, prior_root, &sid, epoch)
}

/// Write-scope prevcommit over the PRIOR `(write_secret, write_epoch)`:
/// `sha256(label ‖ 0x00 ‖ write_secret ‖ epoch_le)`. Retained writers verify
/// it against the secrets they hold — chain continuity, A.5 shape.
pub fn write_scope_prevcommit(write_secret: &[u8; 32], epoch: u32) -> String {
    let mut h = Sha256::new();
    h.update(WRITE_SCOPE_PREVCOMMIT_LABEL);
    h.update([0u8]);
    h.update(write_secret);
    h.update(epoch.to_le_bytes());
    hex::encode(h.finalize())
}

/// Envelope seal key for the outer wrap content (operator-opaque; any holder
/// of the prior root — including a not-yet-excluded member — can open the
/// envelope, but slot secrets stay per-member).
fn rekey_seal_key(prior_root: &[u8; 32], sid: &[u8; 32], epoch: u32) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(REKEY_SEAL_LABEL), prior_root);
    let mut info = Vec::with_capacity(40);
    info.extend_from_slice(sid);
    info.extend_from_slice(&epoch.to_le_bytes());
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("hkdf 32 bytes is valid");
    out
}

/// Opaque per-member slot hint. Only someone holding the prior root AND
/// knowing the member npub can compute it — the git node never learns member
/// identities from a rekey.
fn slot_hint(prior_root: &[u8; 32], sid: &[u8; 32], epoch: u32, member_pub: &PublicKey) -> String {
    let mut h = Sha256::new();
    h.update(REKEY_SLOT_LABEL);
    h.update([0u8]);
    h.update(prior_root);
    h.update(sid);
    h.update(epoch.to_le_bytes());
    h.update(member_pub.to_bytes());
    hex::encode(h.finalize())
}

/// State-scope slot payload: the refounded community (root roll + `#state`
/// rekey) plus the Control republish (roster + banlist snapshot) — the
/// native-layer embodiment of "republish Control editions".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSlot {
    pub community_root: String,
    pub state_key: String,
    pub epoch: u32,
    pub roster: Vec<RosterEntry>,
    #[serde(default)]
    pub banned: Vec<BanEntry>,
}

/// Collab-scope slot payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollabSlot {
    pub collab_key: String,
    pub epoch: u32,
}

/// Write-scope slot payload (push-role members only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteSlot {
    pub write_secret: String,
    pub epoch: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct WireSlot {
    hint: String,
    eph_pub: String,
    ct: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RekeyContent {
    v: u32,
    #[serde(rename = "type")]
    typ: String,
    scope: String,
    epoch: u32,
    slots: Vec<WireSlot>,
}

const REKEY_TYPE: &str = "cord-git-rekey";

/// Build one rekey: inner 3303 rumor signed by the TENANT hosting key, outer
/// 1059 wrap signed by the derived rekey-pseudonym key for
/// (prior_root, scope, new_epoch).
///
/// `slots` = (member identity pubkey, serialized slot payload) for every
/// member retained IN THIS SCOPE. `prevcommit` MUST be present for the write
/// scope (over the prior write secrets) and absent otherwise.
///
/// `epoch_scopes` = the FULL set of scopes this epoch rotates (all three for
/// a refounding/revoke; write-only for a demote). It rides in the
/// tenant-signed `scopes` tag so any single observed genuine rekey tells a
/// folding member exactly which sibling rekeys the epoch requires —
/// epoch-atomic fold (GitLab !12): a member refuses to apply anything until
/// every scope in the set is observed and verified, which is what
/// distinguishes a demote epoch (write-scope-only BY DESIGN) from a partially
/// withheld revoke epoch.
///
/// Returns the outer wrap plus the raw inner rumor JSON bytes (retained on
/// disk for the byte-exact flip discipline).
#[allow(clippy::too_many_arguments)]
pub fn build_rekey(
    hosting: &Keys,
    community_id_hex: &str,
    prior_root: &[u8; 32],
    scope: Scope,
    new_epoch: u32,
    slots: &[(PublicKey, Vec<u8>)],
    prevcommit: Option<&str>,
    epoch_scopes: &[Scope],
) -> Result<(Event, Vec<u8>)> {
    match (scope, prevcommit) {
        (Scope::Write, Some(_)) | (Scope::State, None) | (Scope::Collab, None) => {}
        (Scope::Write, None) => bail!("write-scope rekey requires a prevcommit"),
        (_, Some(_)) => bail!("prevcommit is write-scope-only"),
    }
    if !epoch_scopes.contains(&scope) {
        bail!("epoch scope set must contain the rekey's own scope");
    }
    let sid = scope_id(scope, community_id_hex)?;

    let mut wire_slots = Vec::with_capacity(slots.len());
    for (member_pub, payload) in slots {
        // Fresh ephemeral key per slot — never reused (NIP-44 to the member).
        let eph = Keys::generate();
        let ct = nip44::encrypt(eph.secret_key(), member_pub, payload, nip44::Version::V2)
            .map_err(|e| anyhow!("nip44 slot encrypt: {e}"))?;
        wire_slots.push(WireSlot {
            hint: slot_hint(prior_root, &sid, new_epoch, member_pub),
            eph_pub: eph.public_key().to_hex(),
            ct,
        });
    }

    let content = serde_json::to_string(&RekeyContent {
        v: 1,
        typ: REKEY_TYPE.to_string(),
        scope: scope.name().to_string(),
        epoch: new_epoch,
        slots: wire_slots,
    })?;

    let mut tags = vec![
        Tag::custom("cgc", vec![community_id_hex.to_string()]),
        Tag::custom("scope", vec![hex::encode(sid)]),
        Tag::custom("epoch", vec![new_epoch.to_string()]),
        Tag::custom("scopes", vec![render_scope_set(epoch_scopes)]),
    ];
    if let Some(pc) = prevcommit {
        tags.push(Tag::custom("prevcommit", vec![pc.to_string()]));
    }
    // Inner: SIGNED by the tenant — the sole authenticity root ("authority is
    // rejection": every member can derive the outer key, so the outer proves
    // nothing about who built the rekey).
    let inner = EventBuilder::new(Kind::Custom(KIND_REKEY), content)
        .tags(tags)
        .finalize(hosting)?;
    let raw = inner.as_json().into_bytes();

    let seal_key = rekey_seal_key(prior_root, &sid, new_epoch);
    let sealed = crypto::seal_symmetric(&seal_key, &raw)?;
    let outer_content = base64::engine::general_purpose::STANDARD.encode(sealed);

    let addr = rekey_address(prior_root, community_id_hex, scope, new_epoch)?;
    let outer = EventBuilder::new(Kind::Custom(KIND_WRAP), outer_content)
        .custom_created_at(Timestamp::tweaked(0..172_800))
        .finalize(&addr)?;
    Ok((outer, raw))
}

/// One verified rekey as seen by a member.
#[derive(Debug)]
pub struct ParsedRekey {
    pub scope: Scope,
    pub epoch: u32,
    /// The epoch's full expected scope set from the tenant-signed `scopes`
    /// tag (GitLab !12): the fold refuses to apply anything until every
    /// scope in this set is observed and verified.
    pub epoch_scopes: Vec<Scope>,
    /// This member's decrypted slot payload, if they were retained in this
    /// scope. `None` = no slot: for the write scope that means demoted or
    /// never-had-push; for the state scope, excluded from the refounding.
    pub slot: Option<Vec<u8>>,
}

/// Verify + open one rekey wrap for `member_keys`, expecting (scope,
/// expect_epoch) derived from the member's CURRENT (root, epoch).
///
/// Rejects: outer signer ≠ the locally-derived address key; bad outer/inner
/// signatures; inner not signed by the tenant (forgeries by other/removed
/// members, who CAN derive the address key); wrong kind/type; `cgc` community
/// mismatch (cross-repo replay); epoch mismatch (cross-epoch replay); and —
/// when the member holds prior write secrets — a write-scope `prevcommit`
/// that does not match them.
#[allow(clippy::too_many_arguments)]
pub fn parse_rekey(
    wrap: &Event,
    community_id_hex: &str,
    tenant_hex: &str,
    prior_root: &[u8; 32],
    scope: Scope,
    expect_epoch: u32,
    member_keys: &Keys,
    prior_write: Option<(&[u8; 32], u32)>,
) -> Result<ParsedRekey> {
    wrap.verify()
        .map_err(|e| anyhow!("rekey wrap has an invalid signature: {e}"))?;
    if wrap.kind != Kind::Custom(KIND_WRAP) {
        bail!("not a 1059 wrap");
    }
    let addr = rekey_address(prior_root, community_id_hex, scope, expect_epoch)?;
    if wrap.pubkey != addr.public_key() {
        bail!("wrap outer signer is not the derived rekey address for this scope/epoch");
    }
    let sid = scope_id(scope, community_id_hex)?;
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(wrap.content.as_bytes())
        .map_err(|_| anyhow!("rekey wrap content is not base64"))?;
    let seal_key = rekey_seal_key(prior_root, &sid, expect_epoch);
    let raw = crypto::open_symmetric(&seal_key, &sealed)?;
    let inner = Event::from_json(String::from_utf8_lossy(&raw).as_ref())
        .map_err(|e| anyhow!("sealed rekey payload is not an event: {e}"))?;
    inner
        .verify()
        .map_err(|e| anyhow!("inner rekey rumor has an invalid signature: {e}"))?;
    // AUTHORITY: only the tenant may mint rekeys.
    if inner.pubkey.to_hex() != tenant_hex {
        bail!("rekey rumor is not signed by the tenant — forged rekey rejected");
    }
    if inner.kind != Kind::Custom(KIND_REKEY) {
        bail!("sealed rumor is not a 3303 rekey");
    }
    let tag = |name: &str| -> Option<String> {
        inner.tags.iter().find_map(|t| {
            let v = t.clone().to_vec();
            if v.len() >= 2 && v[0] == name {
                Some(v[1].clone())
            } else {
                None
            }
        })
    };
    if tag("cgc").as_deref() != Some(community_id_hex) {
        bail!("rekey is bound to a different community (cross-repo replay rejected)");
    }
    if tag("scope").as_deref() != Some(hex::encode(sid).as_str()) {
        bail!("rekey scope tag mismatch");
    }
    if tag("epoch").as_deref() != Some(expect_epoch.to_string().as_str()) {
        bail!("rekey epoch tag mismatch (cross-epoch replay rejected)");
    }
    // The epoch's expected scope set (GitLab !12): tenant-signed, so any
    // single genuine rekey is authoritative for which sibling rekeys the
    // epoch requires. Must be present, well-formed, and contain this scope.
    let scopes_tag = tag("scopes")
        .ok_or_else(|| anyhow!("rekey is missing its epoch scope-set tag"))?;
    let epoch_scopes = parse_scope_set(&scopes_tag)?;
    if !epoch_scopes.contains(&scope) {
        bail!("rekey scope-set tag does not list its own scope");
    }
    let content: RekeyContent =
        serde_json::from_str(&inner.content).context("rekey content is not valid")?;
    if content.typ != REKEY_TYPE || content.v != 1 {
        bail!("not a cord-git rekey payload");
    }
    if content.scope != scope.name() || content.epoch != expect_epoch {
        bail!("rekey payload scope/epoch does not match its tags");
    }
    if scope == Scope::Write {
        let pc = tag("prevcommit")
            .ok_or_else(|| anyhow!("write-scope rekey is missing its prevcommit"))?;
        if let Some((prior_secret, prior_epoch)) = prior_write {
            if pc != write_scope_prevcommit(prior_secret, prior_epoch) {
                bail!(
                    "write-scope prevcommit does not match the held (write_secret, epoch) — \
                     desynced or forged rekey rejected"
                );
            }
        }
    }

    // Find our slot by hint; decrypt with NIP-44 (our sk, slot ephemeral pk).
    let my_hint = slot_hint(prior_root, &sid, expect_epoch, &member_keys.public_key());
    let mut slot = None;
    for ws in &content.slots {
        if ws.hint == my_hint {
            let eph_pub = PublicKey::from_hex(&ws.eph_pub)
                .map_err(|e| anyhow!("bad slot ephemeral pubkey: {e}"))?;
            let pt = nip44::decrypt_to_bytes(member_keys.secret_key(), &eph_pub, &ws.ct)
                .map_err(|e| anyhow!("slot decrypt failed: {e}"))?;
            slot = Some(pt);
            break;
        }
    }
    Ok(ParsedRekey {
        scope,
        epoch: expect_epoch,
        epoch_scopes,
        slot,
    })
}

fn is_hex_exact(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl StateSlot {
    pub fn validate(&self) -> Result<()> {
        if !is_hex_exact(&self.community_root, 64) || !is_hex_exact(&self.state_key, 64) {
            bail!("state slot carries invalid hex secrets");
        }
        Ok(())
    }
}

impl CollabSlot {
    pub fn validate(&self) -> Result<()> {
        if !is_hex_exact(&self.collab_key, 64) {
            bail!("collab slot carries an invalid hex key");
        }
        Ok(())
    }
}

impl WriteSlot {
    pub fn validate(&self) -> Result<()> {
        if !is_hex_exact(&self.write_secret, 64) {
            bail!("write slot carries an invalid hex secret");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::Role;

    fn cid() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn scope_ids_are_distinct_and_deterministic() {
        let c = cid();
        let w1 = scope_id(Scope::Write, &c).unwrap();
        let w2 = scope_id(Scope::Write, &c).unwrap();
        assert_eq!(w1, w2);
        let s = scope_id(Scope::State, &c).unwrap();
        let co = scope_id(Scope::Collab, &c).unwrap();
        assert_ne!(w1, s);
        assert_ne!(w1, co);
        assert_ne!(s, co);
        // Bound to the community id.
        let other = scope_id(Scope::Write, &"cd".repeat(32)).unwrap();
        assert_ne!(w1, other);
        // Matches the normative formula: sha256(label || 0x00 || community_id).
        let mut h = Sha256::new();
        h.update(b"cord-git/write-scope-id/v1");
        h.update([0u8]);
        h.update(hex::decode(&c).unwrap());
        let expect: [u8; 32] = h.finalize().into();
        assert_eq!(w1, expect);
    }

    #[test]
    fn rekey_address_binds_root_scope_epoch() {
        let c = cid();
        let root_a = [1u8; 32];
        let root_b = [2u8; 32];
        let a = rekey_address(&root_a, &c, Scope::Write, 1).unwrap();
        let a2 = rekey_address(&root_a, &c, Scope::Write, 1).unwrap();
        assert_eq!(a.public_key(), a2.public_key()); // deterministic
        for other in [
            rekey_address(&root_b, &c, Scope::Write, 1).unwrap(), // root
            rekey_address(&root_a, &c, Scope::Write, 2).unwrap(), // epoch
            rekey_address(&root_a, &c, Scope::State, 1).unwrap(), // scope
        ] {
            assert_ne!(a.public_key(), other.public_key());
        }
        // Dedicated write-scope address == group_key over the normative parts.
        let sid = scope_id(Scope::Write, &c).unwrap();
        let direct = group_key(b"concord/rekey-pseudonym", &root_a, &sid, 1).unwrap();
        assert_eq!(a.public_key(), direct.public_key());
    }

    #[test]
    fn prevcommit_binds_secret_and_epoch() {
        let s1 = [3u8; 32];
        let s2 = [4u8; 32];
        let a = write_scope_prevcommit(&s1, 0);
        assert_eq!(a, write_scope_prevcommit(&s1, 0)); // deterministic
        assert_ne!(a, write_scope_prevcommit(&s2, 0)); // secret-bound
        assert_ne!(a, write_scope_prevcommit(&s1, 1)); // epoch-bound
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn rekey_roundtrip_write_scope() {
        let hosting = Keys::generate();
        let tenant = hosting.public_key().to_hex();
        let member = Keys::generate();
        let outsider = Keys::generate();
        let c = cid();
        let root = [7u8; 32];
        let old_secret = [9u8; 32];
        let new_secret = hex::encode([8u8; 32]);
        let pc = write_scope_prevcommit(&old_secret, 0);
        let payload = serde_json::to_vec(&WriteSlot {
            write_secret: new_secret.clone(),
            epoch: 1,
        })
        .unwrap();
        let (wrap, raw) = build_rekey(
            &hosting,
            &c,
            &root,
            Scope::Write,
            1,
            &[(member.public_key(), payload)],
            Some(&pc),
            &[Scope::Write],
        )
        .unwrap();
        // Raw retained bytes are a verifiable signed rumor (flip discipline).
        let inner = Event::from_json(String::from_utf8(raw).unwrap()).unwrap();
        inner.verify().unwrap();
        // No member identity or secret appears on the wire.
        let wire = wrap.as_json();
        assert!(!wire.contains(&member.public_key().to_hex()));
        assert!(!wire.contains(&new_secret));

        // Retained member (holding the prior write secrets) applies it.
        let parsed = parse_rekey(
            &wrap, &c, &tenant, &root, Scope::Write, 1, &member,
            Some((&old_secret, 0)),
        )
        .unwrap();
        let slot: WriteSlot = serde_json::from_slice(&parsed.slot.unwrap()).unwrap();
        slot.validate().unwrap();
        assert_eq!(slot.write_secret, new_secret);
        assert_eq!(slot.epoch, 1);

        // A member with NO slot sees the rekey but concludes demoted/never-had.
        let parsed = parse_rekey(
            &wrap, &c, &tenant, &root, Scope::Write, 1, &outsider, None,
        )
        .unwrap();
        assert!(parsed.slot.is_none());

        // Wrong prior secrets → prevcommit mismatch → rejected.
        assert!(parse_rekey(
            &wrap, &c, &tenant, &root, Scope::Write, 1, &member,
            Some((&[0u8; 32], 0)),
        )
        .is_err());
        // Wrong expected epoch → address/epoch mismatch → rejected.
        assert!(parse_rekey(
            &wrap, &c, &tenant, &root, Scope::Write, 2, &member,
            Some((&old_secret, 0)),
        )
        .is_err());
        // Wrong root (post-roll member) cannot even locate/open it.
        assert!(parse_rekey(
            &wrap, &c, &tenant, &[0u8; 32], Scope::Write, 1, &member,
            Some((&old_secret, 0)),
        )
        .is_err());
    }

    #[test]
    fn forged_rekey_by_non_tenant_is_rejected() {
        // A removed member holds the prior root, so they CAN derive the
        // address key and mint a well-formed wrap — the tenant-signature
        // check is what kills it.
        let hosting = Keys::generate();
        let tenant = hosting.public_key().to_hex();
        let forger = Keys::generate(); // removed member's identity
        let victim = Keys::generate();
        let c = cid();
        let root = [7u8; 32];
        let payload = serde_json::to_vec(&StateSlot {
            community_root: hex::encode([6u8; 32]),
            state_key: hex::encode([5u8; 32]),
            epoch: 1,
            roster: vec![RosterEntry {
                npub: victim.public_key().to_hex(),
                role: Role::Read,
                granted_at: 0,
            }],
            banned: vec![],
        })
        .unwrap();
        // Forger signs the inner rumor with their own key.
        let (forged, _raw) = build_rekey(
            &forger, &c, &root, Scope::State, 1,
            &[(victim.public_key(), payload.clone())],
            None,
            &Scope::all(),
        )
        .unwrap();
        assert!(parse_rekey(&forged, &c, &tenant, &root, Scope::State, 1, &victim, None).is_err());

        // The genuine tenant-signed one passes.
        let (real, _raw) = build_rekey(
            &hosting, &c, &root, Scope::State, 1,
            &[(victim.public_key(), payload)],
            None,
            &Scope::all(),
        )
        .unwrap();
        let parsed =
            parse_rekey(&real, &c, &tenant, &root, Scope::State, 1, &victim, None).unwrap();
        let slot: StateSlot = serde_json::from_slice(&parsed.slot.unwrap()).unwrap();
        slot.validate().unwrap();
    }

    #[test]
    fn rekey_is_community_bound() {
        let hosting = Keys::generate();
        let tenant = hosting.public_key().to_hex();
        let member = Keys::generate();
        let root = [7u8; 32];
        let payload = serde_json::to_vec(&CollabSlot {
            collab_key: hex::encode([5u8; 32]),
            epoch: 1,
        })
        .unwrap();
        let (wrap, _raw) = build_rekey(
            &hosting, &cid(), &root, Scope::Collab, 1,
            &[(member.public_key(), payload)],
            None,
            &Scope::all(),
        )
        .unwrap();
        // Same wrap presented under another community id: the derived address
        // and scope id both diverge → rejected (cross-repo replay).
        assert!(parse_rekey(
            &wrap, &"cd".repeat(32), &tenant, &root, Scope::Collab, 1, &member, None
        )
        .is_err());
    }

    #[test]
    fn prevcommit_shape_is_enforced_at_build() {
        let hosting = Keys::generate();
        let root = [7u8; 32];
        // Write scope without prevcommit refused.
        assert!(
            build_rekey(&hosting, &cid(), &root, Scope::Write, 1, &[], None, &[Scope::Write])
                .is_err()
        );
        // Channel scope with prevcommit refused.
        let pc = write_scope_prevcommit(&[1u8; 32], 0);
        assert!(build_rekey(
            &hosting,
            &cid(),
            &root,
            Scope::State,
            1,
            &[],
            Some(&pc),
            &[Scope::State]
        )
        .is_err());
        // A rekey whose scope set omits its own scope is refused.
        assert!(build_rekey(
            &hosting,
            &cid(),
            &root,
            Scope::State,
            1,
            &[],
            None,
            &[Scope::Collab]
        )
        .is_err());
    }

    #[test]
    fn scope_set_tag_roundtrip_and_strictness() {
        let hosting = Keys::generate();
        let tenant = hosting.public_key().to_hex();
        let member = Keys::generate();
        let root = [7u8; 32];
        let payload = serde_json::to_vec(&CollabSlot {
            collab_key: hex::encode([5u8; 32]),
            epoch: 1,
        })
        .unwrap();
        // Demote-shape epoch: write-only is expressible...
        let pc = write_scope_prevcommit(&[3u8; 32], 0);
        let (w_wrap, _) = build_rekey(
            &hosting,
            &cid(),
            &root,
            Scope::Write,
            1,
            &[(member.public_key(), serde_json::to_vec(&WriteSlot {
                write_secret: hex::encode([6u8; 32]),
                epoch: 1,
            })
            .unwrap())],
            Some(&pc),
            &[Scope::Write],
        )
        .unwrap();
        let parsed = parse_rekey(
            &w_wrap,
            &cid(),
            &tenant,
            &root,
            Scope::Write,
            1,
            &member,
            Some((&[3u8; 32], 0)),
        )
        .unwrap();
        assert_eq!(parsed.epoch_scopes, vec![Scope::Write]);
        // ...and a full refounding set round-trips in canonical order.
        let (c_wrap, _) = build_rekey(
            &hosting,
            &cid(),
            &root,
            Scope::Collab,
            1,
            &[(member.public_key(), payload)],
            None,
            &[Scope::Write, Scope::Collab, Scope::State], // order normalized
        )
        .unwrap();
        let parsed =
            parse_rekey(&c_wrap, &cid(), &tenant, &root, Scope::Collab, 1, &member, None).unwrap();
        assert_eq!(
            parsed.epoch_scopes,
            vec![Scope::State, Scope::Collab, Scope::Write]
        );
    }

    #[test]
    fn scope_set_parser_rejects_garbage() {
        assert!(parse_scope_set("state,collab,write").is_ok());
        assert!(parse_scope_set("write").is_ok());
        assert!(parse_scope_set("").is_err());
        assert!(parse_scope_set("state,state").is_err()); // dup
        assert!(parse_scope_set("state,root").is_err()); // unknown name
        assert!(parse_scope_set(" state").is_err()); // whitespace
        // Rendering is canonical (sorted, deduped).
        assert_eq!(
            render_scope_set(&[Scope::Write, Scope::State]),
            "state,write"
        );
    }
}
