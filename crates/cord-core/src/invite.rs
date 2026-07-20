//! Direct Invite (kind-3313 NIP-59 giftwrap) and guestbook Join (1059 wrap).
//!
//! Plan §2/§4 (Direct Invite row) and spec §4 invite/join [D]:
//! - The invite bundle carries everything a member needs (community id, node
//!   coordinates, channel keys, `write_secret` IFF push role) inside a
//!   kind-3313 rumor, gift-wrapped FROM AN EPHEMERAL SIGNER and delivered to
//!   the invitee's OWN inbox relay — NORMATIVE: never to the git nodes
//!   (`NGIT_PRIVATE_ACCEPT_DIRECT_INVITES=false` stays false server-side).
//! - The guestbook Join is published only AFTER the joiner holds the bundle;
//!   its OUTER 1059 is signed by the derived guestbook stream key (registered
//!   in the 30640 `aux` set), never the member npub. The inner Join rumor is a
//!   SIGNED event (member npub) sealed under a `#collab`-derived key, and its
//!   raw JSON bytes are retained on disk for a future byte-exact flip-public
//!   republish.
//!
//! This is the CORD-git-native simplified layer; full Concord roster-fold
//! conformance is deferred behind the KeyBackend seam (spec §7). The Join
//! rumor kind (3314) and the `cgc` community-binding tag are native-layer
//! conventions (issue !2 direction), a documented divergence from Concord's
//! mandated `channel`/`epoch` tags.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use nostr::nips::nip59::{GiftWrapBuilder, UnwrappedGift};
use nostr::prelude::{FinalizeEvent, FinalizeUnsignedEvent};
use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, Timestamp};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::keystore::{Keystore, Role, RosterEntry};

/// Direct invite rumor kind (Concord Direct Invite).
pub const KIND_INVITE: u16 = 3313;
/// NIP-59 gift wrap / CORD stream wrap outer kind.
pub const KIND_WRAP: u16 = 1059;
/// Guestbook Join rumor kind (CORD-git-native placeholder).
pub const KIND_JOIN: u16 = 3314;

/// The `cord_git` extension block of the invite bundle (plan §2, Direct
/// Invite row): alias/namespace, blob servers, role, and `write_secret` IFF
/// the invitee is granted the push role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CordGitExt {
    /// Server-side alias (32-hex) the repo is registered under.
    pub alias: String,
    /// Node blob server base URLs.
    pub servers: Vec<String>,
    /// Granted role.
    pub role: Role,
    /// Present IFF `role == write`. NEVER present on read invites.
    pub write_secret: Option<String>,
    /// `#state` channel key (hex).
    pub state_key: String,
    /// `#collab` channel key (hex) — also derives the guestbook stream keys.
    pub collab_key: String,
    /// Community root secret (hex) — derives the rekey-pseudonym addresses a
    /// member folds rotations from. Absent only in pre-4a invites.
    #[serde(default)]
    pub community_root: Option<String>,
    /// Current write-key epoch.
    pub epoch: u32,
    /// Roster snapshot at invite time.
    pub roster: Vec<RosterEntry>,
}

/// The kind-3313 invite bundle (rumor content). Top level = the community
/// coordinates every CORD invite carries; `cord_git` = the extension block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteBundle {
    pub v: u32,
    #[serde(rename = "type")]
    pub typ: String,
    pub community_id: String,
    /// Tenant x-only pubkey hex (the 30640 author) — the community root the
    /// joiner verifies registrations against.
    pub tenant_pub: String,
    /// Owner salt (hex) — lets the joiner check the self-certifying id.
    pub owner_salt: String,
    pub repo_name: String,
    /// Git node relay URLs.
    pub relays: Vec<String>,
    pub cord_git: CordGitExt,
}

const BUNDLE_TYPE: &str = "cord-git-invite";

fn is_hex_exact(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl InviteBundle {
    /// Build the bundle for one grant from the inviter's keystore.
    /// `write_secret` is included IFF the granted role is `write`.
    pub fn from_keystore(ks: &Keystore, role: Role) -> Result<Self> {
        let write_secret = match role {
            Role::Write => Some(
                ks.write_secret
                    .clone()
                    .ok_or_else(|| anyhow!("cannot grant write: this keystore has no write_secret"))?,
            ),
            Role::Read => None,
        };
        Ok(Self {
            v: 1,
            typ: BUNDLE_TYPE.to_string(),
            community_id: ks.community_id.clone(),
            tenant_pub: ks.tenant_hex()?,
            owner_salt: ks.owner_salt.clone(),
            repo_name: ks.repo_name.clone(),
            relays: ks.relays.clone(),
            cord_git: CordGitExt {
                alias: ks.alias.clone(),
                servers: ks.servers.clone(),
                role,
                write_secret,
                state_key: ks.state_key.clone(),
                collab_key: ks.collab_key.clone(),
                community_root: ks.community_root.clone(),
                epoch: ks.epoch,
                roster: ks.roster.clone(),
            },
        })
    }

    /// Validate everything a joiner must not trust blindly: shape, hex
    /// discipline (the community id is later used in filesystem paths), the
    /// self-certifying community id, and role/secret coherence.
    pub fn validate(&self) -> Result<()> {
        if self.typ != BUNDLE_TYPE || self.v != 1 {
            bail!("not a cord-git invite bundle (type/version mismatch)");
        }
        if !is_hex_exact(&self.community_id, 64) {
            bail!("invalid community id in invite (expected 64 lowercase hex)");
        }
        let tenant = PublicKey::from_hex(&self.tenant_pub)
            .map_err(|e| anyhow!("invalid tenant_pub in invite: {e}"))?;
        if !is_hex_exact(&self.owner_salt, 64) {
            bail!("invalid owner_salt in invite");
        }
        let mut salt = [0u8; 32];
        hex::decode_to_slice(&self.owner_salt, &mut salt)
            .map_err(|_| anyhow!("invalid owner_salt hex"))?;
        // Self-certifying check: the community id must bind (tenant, salt).
        if crypto::community_id(&tenant, &salt) != self.community_id {
            bail!("invite community id does not match tenant_pub+owner_salt (forged or corrupted)");
        }
        if !is_hex_exact(&self.cord_git.alias, 32) {
            bail!("invalid alias in invite");
        }
        if !is_hex_exact(&self.cord_git.state_key, 64) || !is_hex_exact(&self.cord_git.collab_key, 64)
        {
            bail!("invalid channel keys in invite");
        }
        if let Some(root) = &self.cord_git.community_root {
            if !is_hex_exact(root, 64) {
                bail!("invalid community_root in invite");
            }
        }
        match (self.cord_git.role, &self.cord_git.write_secret) {
            (Role::Write, Some(ws)) if is_hex_exact(ws, 64) => {}
            (Role::Write, _) => bail!("write invite is missing a valid write_secret"),
            (Role::Read, None) => {}
            (Role::Read, Some(_)) => {
                bail!("read invite carries a write_secret — refusing (role/secret incoherence)")
            }
        }
        if self.relays.is_empty() || self.cord_git.servers.is_empty() {
            bail!("invite is missing node relay/server coordinates");
        }
        Ok(())
    }

    /// Materialize a MEMBER keystore from a validated bundle. Never contains
    /// the hosting nsec; the tenant is known only by its pubkey.
    pub fn into_keystore(self) -> Keystore {
        Keystore {
            community_id: self.community_id,
            repo_name: self.repo_name,
            hosting_nsec: None,
            tenant_pub: Some(self.tenant_pub),
            owner_salt: self.owner_salt,
            state_key: self.cord_git.state_key,
            collab_key: self.cord_git.collab_key,
            community_root: self.cord_git.community_root,
            write_secret: self.cord_git.write_secret,
            epoch: self.cord_git.epoch,
            alias: self.cord_git.alias,
            relays: self.relays,
            servers: self.cord_git.servers,
            role: self.cord_git.role,
            manifest_prev: None,
            roster: self.cord_git.roster,
            banned: Vec::new(),
        }
    }
}

/// Gift-wrap an invite bundle for `invitee`: kind-3313 rumor, sealed and
/// wrapped by a FRESH EPHEMERAL signer (NIP-59). Nothing on the wire links to
/// the inviter or the community; only the invitee can open it.
pub fn wrap_invite(bundle: &InviteBundle, invitee: &PublicKey) -> Result<Event> {
    bundle.validate()?;
    let eph = Keys::generate();
    let content = serde_json::to_string(bundle)?;
    let mut rumor = EventBuilder::new(Kind::Custom(KIND_INVITE), content)
        .finalize_unsigned(eph.public_key());
    rumor.ensure_id();
    GiftWrapBuilder::new(*invitee, rumor)
        .finalize(&eph)
        .map_err(|e| anyhow!("gift wrap failed: {e}"))
}

/// Verify + unwrap the outer/seal layers of a 3313-family whisper addressed
/// to `keys`, returning the rumor content. Shared by invite and promotion.
fn unwrap_3313(keys: &Keys, wrap: &Event) -> Result<String> {
    wrap.verify()
        .map_err(|e| anyhow!("wrap has an invalid signature: {e}"))?;
    if wrap.kind != Kind::Custom(KIND_WRAP) {
        bail!("not a gift wrap (kind {})", wrap.kind.as_u16());
    }
    let gift = UnwrappedGift::from_gift_wrap(keys, wrap)
        .map_err(|e| anyhow!("could not unwrap (not addressed to this key?): {e}"))?;
    if gift.rumor.kind != Kind::Custom(KIND_INVITE) {
        bail!(
            "unwrapped rumor is not a 3313 whisper (kind {})",
            gift.rumor.kind.as_u16()
        );
    }
    Ok(gift.rumor.content)
}

/// Unwrap + validate an invite addressed to `keys`. The wrap signature is
/// verified BEFORE any decryption (never trust relay-fetched bytes), the seal
/// is verified inside `UnwrappedGift`, and the bundle passes `validate()`.
pub fn unwrap_invite(keys: &Keys, wrap: &Event) -> Result<InviteBundle> {
    let content = unwrap_3313(keys, wrap)?;
    let bundle: InviteBundle =
        serde_json::from_str(&content).context("invite rumor content is not a valid bundle")?;
    if bundle.typ != BUNDLE_TYPE {
        bail!("3313 whisper is not an invite");
    }
    bundle.validate()?;
    Ok(bundle)
}

/// Promotion whisper payload (plan §2/§4: Promote = Grant + `write_secret`
/// delivery, 3313-style, to the member's OWN inbox relay). Carries only the
/// write-scope secrets — the member already holds the community bundle from
/// their invite; the receiving side validates the delivered secret against
/// the live registration before trusting it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionBundle {
    pub v: u32,
    #[serde(rename = "type")]
    pub typ: String,
    pub community_id: String,
    /// The shared push secret (hex).
    pub write_secret: String,
    /// The epoch the secret is valid for.
    pub epoch: u32,
}

const PROMOTION_TYPE: &str = "cord-git-promotion";

impl PromotionBundle {
    pub fn validate(&self) -> Result<()> {
        if self.typ != PROMOTION_TYPE || self.v != 1 {
            bail!("not a cord-git promotion (type/version mismatch)");
        }
        if !is_hex_exact(&self.community_id, 64) {
            bail!("invalid community id in promotion");
        }
        if !is_hex_exact(&self.write_secret, 64) {
            bail!("invalid write_secret in promotion");
        }
        Ok(())
    }
}

/// Gift-wrap a promotion whisper for `member` (fresh ephemeral signer, same
/// leak discipline as invites: inbox relays only, never the git node).
pub fn wrap_promotion(ks: &Keystore, member: &PublicKey) -> Result<(Event, PromotionBundle)> {
    let bundle = PromotionBundle {
        v: 1,
        typ: PROMOTION_TYPE.to_string(),
        community_id: ks.community_id.clone(),
        write_secret: ks
            .write_secret
            .clone()
            .ok_or_else(|| anyhow!("cannot promote: this keystore has no write_secret"))?,
        epoch: ks.epoch,
    };
    bundle.validate()?;
    let eph = Keys::generate();
    let content = serde_json::to_string(&bundle)?;
    let mut rumor = EventBuilder::new(Kind::Custom(KIND_INVITE), content)
        .finalize_unsigned(eph.public_key());
    rumor.ensure_id();
    let wrap = GiftWrapBuilder::new(*member, rumor)
        .finalize(&eph)
        .map_err(|e| anyhow!("gift wrap failed: {e}"))?;
    Ok((wrap, bundle))
}

/// Unwrap + shape-validate a promotion addressed to `keys`. NOTE: shape only —
/// the caller MUST additionally verify the delivered secret derives a write
/// key listed in the live 30640 (verified against the tenant pubkey from the
/// EXISTING keystore, never from the whisper) before persisting anything.
pub fn unwrap_promotion(keys: &Keys, wrap: &Event) -> Result<PromotionBundle> {
    let content = unwrap_3313(keys, wrap)?;
    let bundle: PromotionBundle =
        serde_json::from_str(&content).context("rumor content is not a promotion")?;
    bundle.validate()?;
    Ok(bundle)
}

/// Build the guestbook Join for `member`. Returns the outer 1059 (signed by
/// the DERIVED guestbook stream key — never the member npub) plus the raw
/// inner rumor JSON bytes, which the caller must retain for flip-public.
pub fn build_join(member: &Keys, ks: &Keystore) -> Result<(Event, Vec<u8>)> {
    // Inner: a SIGNED rumor (real event) by the member identity, bound to this
    // community with a `cgc` tag against cross-repo replay.
    let rumor = EventBuilder::new(Kind::Custom(KIND_JOIN), "")
        .tags(vec![Tag::custom("cgc", vec![ks.community_id.clone()])])
        .finalize(member)?;
    let raw = rumor.as_json().into_bytes();

    // Seal so only members (holders of #collab) can read it; fresh nonce.
    let seal_key = crypto::guestbook_seal_key(&ks.collab_key_bytes()?);
    let sealed = crypto::seal_symmetric(&seal_key, &raw)?;
    let content = base64::engine::general_purpose::STANDARD.encode(sealed);

    // Outer wrap: derived guestbook stream key, timestamp tweaked into the
    // past (NIP-59 discipline; the node rejects future-dating anyway).
    let gb = ks.guestbook_keys()?;
    let outer = EventBuilder::new(Kind::Custom(KIND_WRAP), content)
        .custom_created_at(Timestamp::tweaked(0..172_800))
        .finalize(&gb)?;
    Ok((outer, raw))
}

/// A parsed guestbook Join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinInfo {
    /// Member identity pubkey (x-only hex) — from the signed inner rumor.
    pub member_pub: String,
    /// Inner rumor timestamp.
    pub at: u64,
}

/// Verify + open one guestbook wrap into a Join. Rejects wraps whose outer
/// signer is not the derived guestbook key, wraps that fail signature
/// verification (outer or inner), non-Join rumors, and rumors bound to a
/// different community (`cgc` mismatch — cross-repo replay).
pub fn parse_join(ks: &Keystore, wrap: &Event) -> Result<JoinInfo> {
    wrap.verify()
        .map_err(|e| anyhow!("guestbook wrap has an invalid signature: {e}"))?;
    if wrap.kind != Kind::Custom(KIND_WRAP) {
        bail!("not a 1059 wrap");
    }
    let gb = ks.guestbook_keys()?;
    if wrap.pubkey != gb.public_key() {
        bail!("wrap outer signer is not the derived guestbook stream key");
    }
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(wrap.content.as_bytes())
        .map_err(|_| anyhow!("guestbook wrap content is not base64"))?;
    let seal_key = crypto::guestbook_seal_key(&ks.collab_key_bytes()?);
    let raw = crypto::open_symmetric(&seal_key, &sealed)?;
    let inner = Event::from_json(String::from_utf8_lossy(&raw).as_ref())
        .map_err(|e| anyhow!("sealed guestbook payload is not an event: {e}"))?;
    inner
        .verify()
        .map_err(|e| anyhow!("inner join rumor has an invalid signature: {e}"))?;
    if inner.kind != Kind::Custom(KIND_JOIN) {
        bail!("sealed rumor is not a guestbook join (kind {})", inner.kind.as_u16());
    }
    let cgc = inner
        .tags
        .iter()
        .find_map(|t| {
            let v = t.clone().to_vec();
            if v.len() >= 2 && v[0] == "cgc" {
                Some(v[1].clone())
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("join rumor is missing its cgc community binding"))?;
    if cgc != ks.community_id {
        bail!("join rumor is bound to a different community (cross-repo replay rejected)");
    }
    Ok(JoinInfo {
        member_pub: inner.pubkey.to_hex(),
        at: inner.created_at.as_secs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner_keystore() -> Keystore {
        let hosting = Keys::generate();
        let salt = crypto::random_32();
        let community_id = crypto::community_id(&hosting.public_key(), &salt);
        Keystore {
            community_id,
            repo_name: "demo".into(),
            hosting_nsec: Some(hosting.secret_key().to_secret_hex()),
            tenant_pub: Some(hosting.public_key().to_hex()),
            owner_salt: hex::encode(salt),
            state_key: hex::encode(crypto::random_32()),
            collab_key: hex::encode(crypto::random_32()),
            community_root: Some(hex::encode(crypto::random_32())),
            write_secret: Some(hex::encode(crypto::random_32())),
            epoch: 0,
            alias: hex::encode(crypto::random_32())[..32].to_string(),
            relays: vec!["ws://127.0.0.1:1".into()],
            servers: vec!["http://127.0.0.1:1".into()],
            role: Role::Write,
            manifest_prev: None,
            roster: vec![],
            banned: vec![],
        }
    }

    #[test]
    fn bundle_roundtrip_write_and_read_roles() {
        let ks = owner_keystore();
        let wb = InviteBundle::from_keystore(&ks, Role::Write).unwrap();
        assert_eq!(wb.cord_git.write_secret, ks.write_secret);
        let rb = InviteBundle::from_keystore(&ks, Role::Read).unwrap();
        assert!(rb.cord_git.write_secret.is_none());
        // JSON roundtrip preserves the extension block.
        let json = serde_json::to_string(&wb).unwrap();
        let back: InviteBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, wb);
        back.validate().unwrap();
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let ks = owner_keystore();
        let invitee = Keys::generate();
        let bundle = InviteBundle::from_keystore(&ks, Role::Write).unwrap();
        let wrap = wrap_invite(&bundle, &invitee.public_key()).unwrap();
        // Wire hygiene: outer is 1059, p-tags the invitee, and neither the
        // tenant pubkey nor any secret appears in the wrap JSON.
        assert_eq!(wrap.kind.as_u16(), KIND_WRAP);
        let wire = wrap.as_json();
        assert!(!wire.contains(&ks.tenant_pub.clone().unwrap()));
        assert!(!wire.contains(ks.write_secret.as_ref().unwrap()));
        assert!(!wire.contains(&ks.state_key));
        let got = unwrap_invite(&invitee, &wrap).unwrap();
        assert_eq!(got, bundle);
        // The member keystore never gets the hosting nsec.
        let mks = got.into_keystore();
        assert!(mks.hosting_nsec.is_none());
        assert_eq!(mks.tenant_pub.as_deref(), Some(ks.tenant_hex().unwrap().as_str()));
        assert!(mks.is_write());
    }

    #[test]
    fn unwrap_with_wrong_key_fails() {
        let ks = owner_keystore();
        let invitee = Keys::generate();
        let bundle = InviteBundle::from_keystore(&ks, Role::Read).unwrap();
        let wrap = wrap_invite(&bundle, &invitee.public_key()).unwrap();
        let eve = Keys::generate();
        assert!(unwrap_invite(&eve, &wrap).is_err());
    }

    #[test]
    fn read_invite_carrying_write_secret_is_rejected() {
        let ks = owner_keystore();
        let mut bundle = InviteBundle::from_keystore(&ks, Role::Read).unwrap();
        bundle.cord_git.write_secret = ks.write_secret.clone();
        assert!(bundle.validate().is_err());
        // And a maliciously wrapped one is rejected at unwrap.
        let invitee = Keys::generate();
        let eph = Keys::generate();
        let mut rumor = EventBuilder::new(
            Kind::Custom(KIND_INVITE),
            serde_json::to_string(&bundle).unwrap(),
        )
        .finalize_unsigned(eph.public_key());
        rumor.ensure_id();
        let wrap = GiftWrapBuilder::new(invitee.public_key(), rumor)
            .finalize(&eph)
            .unwrap();
        assert!(unwrap_invite(&invitee, &wrap).is_err());
    }

    #[test]
    fn forged_community_id_is_rejected() {
        let ks = owner_keystore();
        let mut bundle = InviteBundle::from_keystore(&ks, Role::Read).unwrap();
        // Point the bundle at a different community id than (tenant, salt) binds.
        bundle.community_id = "ab".repeat(32);
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn join_roundtrip_and_bindings() {
        let ks = owner_keystore();
        let member = Keys::generate();
        let (outer, raw) = build_join(&member, &ks).unwrap();
        // Outer signer is the derived guestbook key, never the member npub.
        assert_eq!(outer.pubkey, ks.guestbook_keys().unwrap().public_key());
        assert_ne!(outer.pubkey, member.public_key());
        // Raw retained bytes parse + verify standalone (flip discipline).
        let inner = Event::from_json(String::from_utf8(raw).unwrap()).unwrap();
        inner.verify().unwrap();
        let info = parse_join(&ks, &outer).unwrap();
        assert_eq!(info.member_pub, member.public_key().to_hex());

        // Wrong collab key (non-member) cannot read or forge.
        let mut other = ks.clone();
        other.collab_key = hex::encode(crypto::random_32());
        assert!(parse_join(&other, &outer).is_err());

        // A join for another community is rejected (cgc binding).
        let mut other_cid = ks.clone();
        other_cid.community_id = "cd".repeat(32);
        assert!(parse_join(&other_cid, &outer).is_err());

        // An outer wrap signed by the member npub itself is rejected.
        let sealed = outer.content.clone();
        let bad_outer = EventBuilder::new(Kind::Custom(KIND_WRAP), sealed)
            .finalize(&member)
            .unwrap();
        assert!(parse_join(&ks, &bad_outer).is_err());
    }

    #[test]
    fn promotion_roundtrip_and_type_separation() {
        let ks = owner_keystore();
        let member = Keys::generate();
        let (wrap, bundle) = wrap_promotion(&ks, &member.public_key()).unwrap();
        // Secret never on the wire.
        assert!(!wrap.as_json().contains(ks.write_secret.as_ref().unwrap()));
        let got = unwrap_promotion(&member, &wrap).unwrap();
        assert_eq!(got, bundle);
        assert_eq!(got.write_secret, *ks.write_secret.as_ref().unwrap());
        // Wrong recipient cannot open it.
        assert!(unwrap_promotion(&Keys::generate(), &wrap).is_err());
        // A promotion wrap does not parse as an invite, and vice versa.
        assert!(unwrap_invite(&member, &wrap).is_err());
        let inv = InviteBundle::from_keystore(&ks, Role::Read).unwrap();
        let inv_wrap = wrap_invite(&inv, &member.public_key()).unwrap();
        assert!(unwrap_promotion(&member, &inv_wrap).is_err());
    }

    #[test]
    fn invite_bundle_carries_community_root() {
        let ks = owner_keystore();
        let b = InviteBundle::from_keystore(&ks, Role::Read).unwrap();
        assert_eq!(b.cord_git.community_root, ks.community_root);
        let mks = b.into_keystore();
        assert_eq!(mks.community_root, ks.community_root);
        // A malformed root is refused at validation.
        let mut bad = InviteBundle::from_keystore(&ks, Role::Read).unwrap();
        bad.cord_git.community_root = Some("zz".repeat(32));
        assert!(bad.validate().is_err());
    }

    #[test]
    fn registration_carries_aux_pop() {
        let hosting = Keys::generate();
        let w = Keys::generate();
        let gb = Keys::generate();
        let alias = "ab".repeat(16);
        let reg = crate::events::build_registration(
            &hosting,
            &w,
            &[&gb],
            &alias,
            &["ws://x".into()],
            &["http://x".into()],
        )
        .unwrap();
        let tenant = hosting.public_key().to_hex();
        let aux: Vec<Vec<String>> = reg
            .tags
            .iter()
            .map(|t| t.clone().to_vec())
            .filter(|v| v[0] == "aux")
            .collect();
        assert_eq!(aux.len(), 1);
        assert_eq!(aux[0][1], gb.public_key().to_hex());
        assert!(crypto::verify_key_pop(&aux[0][1], &aux[0][2], &tenant, &alias));
    }
}
