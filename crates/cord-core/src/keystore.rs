//! Per-community keystore on disk under `CORD_GIT_HOME`
//! (default `~/.config/cord-git`). Holds every client secret for one
//! community; the server holds none of this. Files are written 0600 and never
//! logged. See design §5.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use nostr::Keys;
use serde::{Deserialize, Serialize};

use crate::crypto;

/// Membership role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Read,
    Write,
}

/// One roster grant recorded by the inviter (owner-rooted; the CORD-git-native
/// simplification of the Concord Roles/Grants fold). Members receive the
/// current snapshot inside their invite bundle.
///
/// NORMATIVE (plan §2, revoke row): push-role conclusions come ONLY from this
/// roster fold plus write-scope key possession — the absence of a write-scope
/// rekey slot means never-had-push or demoted, never "removed from the repo".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterEntry {
    /// Member identity pubkey (x-only hex).
    pub npub: String,
    pub role: Role,
    pub granted_at: u64,
}

/// One banlist entry (Concord Banlist vsk4, native simplification). A ban is
/// what triggers a refounding; it is a distinct, refuse-downgrade record —
/// never inferred from a missing grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanEntry {
    /// Banned identity pubkey (x-only hex).
    pub npub: String,
    pub banned_at: u64,
}

/// The full secret bundle for one community/repo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    pub community_id: String,
    pub repo_name: String,
    /// Hosting npub secret (nsec hex) — the pseudonymous tenant identity that
    /// signs the 30640 registration. Present ONLY on the owner's keystore;
    /// invited members never receive it.
    pub hosting_nsec: Option<String>,
    /// Tenant x-only pubkey hex (the 30640 author). Members verify
    /// registrations and state roots against this; owners can also derive it
    /// from `hosting_nsec`.
    #[serde(default)]
    pub tenant_pub: Option<String>,
    /// 32-byte owner salt (hex) feeding the community id.
    pub owner_salt: String,
    /// Community root secret (hex) — the Concord community_root analog. Feeds
    /// the rekey-pseudonym address derivation (`group_key`); ROLLED on every
    /// refounding (revoke). Members receive it in the invite bundle and via
    /// state-scope rekey slots. Absent only on pre-4a keystores (rotation
    /// flows refuse to run without it).
    #[serde(default)]
    pub community_root: Option<String>,
    /// `#state` channel key (hex) — reads manifests.
    pub state_key: String,
    /// `#collab` channel key (hex) — reserved for Phase 4.
    pub collab_key: String,
    /// `write_secret` (hex) — present only for write-role members; derives the
    /// registered write keypair. Absent (None) for read-only members.
    pub write_secret: Option<String>,
    /// Current epoch (0 in P3).
    pub epoch: u32,
    /// Server-side alias (32-hex) under which this repo is registered.
    pub alias: String,
    /// Node relay URLs (ws/wss).
    pub relays: Vec<String>,
    /// Node blob server base URLs (http/https).
    pub servers: Vec<String>,
    /// This member's role.
    pub role: Role,
    /// Last observed 30641 event id (CAS anchor); None before first push/fetch.
    pub manifest_prev: Option<String>,
    /// Roster grants known locally (owner: authoritative; member: the snapshot
    /// delivered in the invite bundle).
    #[serde(default)]
    pub roster: Vec<RosterEntry>,
    /// Banlist known locally (owner: authoritative; member: snapshot from
    /// state-scope rekey slots).
    #[serde(default)]
    pub banned: Vec<BanEntry>,
    /// Prior `#collab` channel keys retained across refoundings, keyed by the
    /// LAST epoch each key was current for (GitLab #21). These keep
    /// pre-revocation `#collab`/guestbook history readable for retained
    /// members — GitHub-parity: removing a collaborator destroys nothing for
    /// everyone else. STRICTLY read-only AND retirement-bounded: writing
    /// always uses `collab_key`, and wraps matched to a retired key are
    /// rejected unless their inner rumor predates the key's retirement — a
    /// revoked member must not keep WRITE access to history streams either.
    #[serde(default)]
    pub prior_collab_keys: BTreeMap<u32, PriorCollabKey>,
    /// Policy knob (GitLab #21): retain prior `#collab` keys across
    /// refoundings. Default TRUE (GitHub parity). Off = the pre-fix
    /// behaviour, now as a stated policy: every revoke truncates history,
    /// and a device compromise exposes only the current epoch.
    #[serde(default = "default_retain_history")]
    pub retain_collab_history: bool,
}

fn default_retain_history() -> bool {
    true
}

/// Hard cap on retained prior `#collab` keys. Bounds three things at once:
/// rekey-slot payload growth against the NIP-44 plaintext ceiling (a ring
/// that outgrows it would brick `revoke` itself), invite-bundle growth, and
/// what a hostile owner can stuff into a member's keystore via slot priors.
/// At ~90 JSON bytes/entry this stays far below the 64 KiB NIP-44 limit.
pub const MAX_PRIOR_COLLAB_KEYS: usize = 256;

/// One retired `#collab` key (GitLab #21).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorCollabKey {
    /// The retired channel key (hex).
    pub key: String,
    /// When the key stopped being current (unix seconds) — the read-side
    /// acceptance bound for wraps under this key: anything whose INNER rumor
    /// is dated after `retired_at` + slack is a post-revocation injection by
    /// an old-key holder, not history, and is rejected.
    pub retired_at: u64,
}

/// One entry of the readable `#collab` key ring: the current key (unbounded)
/// or a retired prior (bounded by its last epoch + retirement time).
#[derive(Debug, Clone, Copy)]
pub struct CollabRingEntry {
    pub key: [u8; 32],
    /// `None` = the current key; `Some((last_epoch, retired_at))` for priors.
    pub retired: Option<(u32, u64)>,
}

/// The precomputed `#collab` ring: derived stream pubkey → ring entry.
/// Built once per read batch via [`Keystore::collab_ring`].
pub struct CollabRing {
    entries: Vec<(nostr::PublicKey, CollabRingEntry)>,
}

impl CollabRing {
    /// The ring entry whose derived stream key signed this outer author, if
    /// any — current key first, then priors newest-to-oldest.
    pub fn match_author(&self, author: &nostr::PublicKey) -> Option<&CollabRingEntry> {
        self.entries
            .iter()
            .find(|(pk, _)| pk == author)
            .map(|(_, e)| e)
    }
}

impl Keystore {
    /// Root keystore directory (`CORD_GIT_HOME` or `~/.config/cord-git`).
    pub fn home() -> Result<PathBuf> {
        if let Ok(dir) = std::env::var("CORD_GIT_HOME") {
            return Ok(PathBuf::from(dir));
        }
        let base = std::env::var("HOME").context("HOME not set")?;
        Ok(PathBuf::from(base).join(".config").join("cord-git"))
    }

    fn path_for(community_id: &str) -> Result<PathBuf> {
        // The id is joined into a filesystem path — it MUST be exactly 64
        // lowercase hex, or a hostile `.cord-git` pointer could traverse
        // outside the keystore root.
        if community_id.len() != 64
            || !community_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(anyhow!("invalid community id (expected 64 lowercase hex)"));
        }
        Ok(Self::home()?.join(community_id).join("keystore.json"))
    }

    /// 32-byte hex secrets → typed arrays.
    pub fn state_key_bytes(&self) -> Result<[u8; 32]> {
        hex32(&self.state_key)
    }
    pub fn owner_salt_bytes(&self) -> Result<[u8; 32]> {
        hex32(&self.owner_salt)
    }
    pub fn write_secret_bytes(&self) -> Result<Option<[u8; 32]>> {
        match &self.write_secret {
            Some(h) => Ok(Some(hex32(h)?)),
            None => Ok(None),
        }
    }

    pub fn hosting_keys(&self) -> Result<Keys> {
        let nsec = self
            .hosting_nsec
            .as_ref()
            .ok_or_else(|| anyhow!("owner-only operation: this keystore has no hosting nsec"))?;
        Keys::parse(nsec).map_err(|e| anyhow!("bad hosting nsec: {e}"))
    }

    /// `#collab` channel key bytes.
    pub fn collab_key_bytes(&self) -> Result<[u8; 32]> {
        hex32(&self.collab_key)
    }

    /// Community root secret bytes — required by every rotation/refounding
    /// flow (rekey-pseudonym address derivation).
    pub fn community_root_bytes(&self) -> Result<[u8; 32]> {
        let root = self.community_root.as_ref().ok_or_else(|| {
            anyhow!(
                "keystore has no community_root (pre-4a keystore) — \
                 re-create the repo or ask for a fresh invite"
            )
        })?;
        hex32(root)
    }

    /// Is this the owner's keystore (holds the hosting nsec)?
    pub fn is_owner(&self) -> bool {
        self.hosting_nsec.is_some()
    }

    /// Directory holding this community's keystore + retained rumor bytes.
    /// The id is path-validated (64 lowercase hex).
    pub fn community_dir(community_id: &str) -> Result<PathBuf> {
        Ok(Self::path_for(community_id)?
            .parent()
            .expect("keystore path has a parent")
            .to_path_buf())
    }

    /// Derived guestbook stream keypair (shared across members via `#collab`).
    pub fn guestbook_keys(&self) -> Result<Keys> {
        crypto::derive_guestbook_keys(&self.collab_key_bytes()?)
    }

    /// Adopt a rolled `#collab` key, retiring the outgoing one into the
    /// prior-key ring (keyed by the epoch it was last current for) so
    /// pre-refounding history stays readable (GitLab #21). Honors the retain
    /// knob: off = drop all history at the roll instead. No-op when the key
    /// is unchanged (idempotent across resume/re-adoption paths). An entry
    /// already present at this epoch with the SAME key (e.g. merged from an
    /// owner-stamped rekey slot) keeps its authoritative `retired_at`; a
    /// mismatched key is overwritten — the keys we held ourselves win.
    pub fn adopt_collab_key(&mut self, new_key: String) {
        if new_key == self.collab_key {
            return;
        }
        if self.retain_collab_history {
            let outgoing = std::mem::replace(&mut self.collab_key, new_key);
            let entry =
                self.prior_collab_keys
                    .entry(self.epoch)
                    .or_insert_with(|| PriorCollabKey {
                        key: outgoing.clone(),
                        retired_at: crate::events::now_secs(),
                    });
            if entry.key != outgoing {
                entry.key = outgoing;
                entry.retired_at = crate::events::now_secs();
            }
            self.prune_prior_collab_keys();
        } else {
            self.prior_collab_keys.clear();
            self.collab_key = new_key;
        }
    }

    /// Enforce [`MAX_PRIOR_COLLAB_KEYS`], dropping the OLDEST epochs first
    /// (retain-last-N semantics — the documented cost of the cap).
    pub fn prune_prior_collab_keys(&mut self) {
        while self.prior_collab_keys.len() > MAX_PRIOR_COLLAB_KEYS {
            let oldest = *self
                .prior_collab_keys
                .keys()
                .next()
                .expect("non-empty map has a first key");
            self.prior_collab_keys.remove(&oldest);
        }
    }

    /// Every `#collab` key this keystore may READ under: the current key
    /// first, then retained priors newest-to-oldest, each carrying its
    /// (last_epoch, retired_at) acceptance bound. Writing (new wraps, joins,
    /// invites' current key) always uses `collab_key` alone.
    pub fn collab_key_ring(&self) -> Result<Vec<CollabRingEntry>> {
        let mut ring = vec![CollabRingEntry {
            key: self.collab_key_bytes()?,
            retired: None,
        }];
        for (epoch, prior) in self.prior_collab_keys.iter().rev() {
            ring.push(CollabRingEntry {
                key: hex32(&prior.key)?,
                retired: Some((*epoch, prior.retired_at)),
            });
        }
        Ok(ring)
    }

    /// Derived guestbook stream pubkeys (hex) across the whole ring, current
    /// first — the NIP-01 `authors` set for fetching `#collab`/guestbook
    /// wraps: after a refounding, pre-rotation wraps live under the PRIOR
    /// derived stream pubkeys and would otherwise never be fetched at all.
    pub fn guestbook_author_ring(&self) -> Result<Vec<String>> {
        self.collab_key_ring()?
            .iter()
            .map(|e| Ok(crypto::derive_guestbook_keys(&e.key)?.public_key().to_hex()))
            .collect()
    }

    /// Precompute the ring's derived stream pubkeys for batch parsing.
    /// Deriving a stream key is an EC operation and a hostile relay controls
    /// how many wraps a batch contains, so derivation must happen ONCE per
    /// batch (O(wraps + ring)), never per wrap (O(wraps × ring)).
    pub fn collab_ring(&self) -> Result<CollabRing> {
        let mut entries = Vec::new();
        for e in self.collab_key_ring()? {
            entries.push((crypto::derive_guestbook_keys(&e.key)?.public_key(), e));
        }
        Ok(CollabRing { entries })
    }

    /// Derived write keypair (write-role only).
    pub fn write_keys(&self) -> Result<Keys> {
        let secret = self
            .write_secret_bytes()?
            .ok_or_else(|| anyhow!("this keystore is read-only (no write_secret)"))?;
        crypto::derive_write_keys(&secret, self.epoch)
    }

    /// Tenant x-only pubkey hex (the 30640 author). Members carry it as
    /// `tenant_pub`; the owner can also derive it from the hosting nsec.
    pub fn tenant_hex(&self) -> Result<String> {
        if let Some(tp) = &self.tenant_pub {
            let pk = nostr::PublicKey::from_hex(tp)
                .map_err(|e| anyhow!("bad tenant_pub in keystore: {e}"))?;
            return Ok(pk.to_hex());
        }
        Ok(self.hosting_keys()?.public_key().to_hex())
    }

    pub fn is_write(&self) -> bool {
        self.role == Role::Write && self.write_secret.is_some()
    }

    /// Persist atomically with 0600 permissions (created restrictive from the
    /// start — never a world-readable window).
    pub fn save(&self) -> Result<()> {
        let path = Self::path_for(&self.community_id)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            set_dir_permissions_0700(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        write_0600(&tmp, &json)?;
        std::fs::rename(&tmp, &path)?;
        set_permissions_0600(&path)?;
        Ok(())
    }

    pub fn load(community_id: &str) -> Result<Self> {
        let path = Self::path_for(community_id)?;
        let bytes = std::fs::read(&path)
            .with_context(|| format!("no keystore for community {community_id} at {path:?}"))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn exists(community_id: &str) -> bool {
        Self::path_for(community_id)
            .map(|p| p.exists())
            .unwrap_or(false)
    }
}

fn hex32(h: &str) -> Result<[u8; 32]> {
    let v = hex::decode(h).map_err(|_| anyhow!("invalid hex"))?;
    let arr: [u8; 32] = v
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes"))?;
    Ok(arr)
}

#[cfg(unix)]
fn set_permissions_0600(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn write_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn set_dir_permissions_0700(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Only tighten a dir we just created (skip if it already held keystores
    // for other communities — tightening is harmless either way, but don't
    // error on pre-existing).
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = std::fs::set_permissions(path, perms);
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_permissions_0600(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn write_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions_0700(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ks() -> Keystore {
        Keystore {
            community_id: "ab".repeat(32),
            repo_name: "t".into(),
            hosting_nsec: None,
            tenant_pub: None,
            owner_salt: "00".repeat(32),
            community_root: Some("11".repeat(32)),
            state_key: "22".repeat(32),
            collab_key: "33".repeat(32),
            write_secret: None,
            epoch: 0,
            alias: "cd".repeat(16),
            relays: vec![],
            servers: vec![],
            role: Role::Read,
            manifest_prev: None,
            roster: vec![],
            banned: vec![],
            prior_collab_keys: BTreeMap::new(),
            retain_collab_history: true,
        }
    }

    #[test]
    fn adopt_collab_key_retires_into_the_ring() {
        let mut k = ks();
        let k0 = k.collab_key.clone();
        // Same key: no-op (resume/idempotent adoption paths re-adopt).
        k.adopt_collab_key(k0.clone());
        assert!(k.prior_collab_keys.is_empty());
        // Roll at epoch 0, then advance and roll again at epoch 3.
        k.adopt_collab_key("44".repeat(32));
        k.epoch = 3;
        k.adopt_collab_key("55".repeat(32));
        assert_eq!(k.prior_collab_keys.get(&0).unwrap().key, k0);
        assert_eq!(k.prior_collab_keys.get(&3).unwrap().key, "44".repeat(32));
        assert!(k.prior_collab_keys.get(&0).unwrap().retired_at > 0);
        // Ring order: current first (unbounded), then priors newest-to-oldest
        // carrying their (last_epoch, retired_at) bounds.
        let ring = k.collab_key_ring().unwrap();
        assert_eq!(hex::encode(ring[0].key), "55".repeat(32));
        assert!(ring[0].retired.is_none());
        assert_eq!(hex::encode(ring[1].key), "44".repeat(32));
        assert_eq!(ring[1].retired.unwrap().0, 3);
        assert_eq!(hex::encode(ring[2].key), k0);
        assert_eq!(ring[2].retired.unwrap().0, 0);
        // Author ring matches the derived stream key per ring entry.
        let authors = k.guestbook_author_ring().unwrap();
        assert_eq!(authors.len(), 3);
        assert_eq!(
            authors[0],
            k.guestbook_keys().unwrap().public_key().to_hex()
        );
        // An owner-stamped entry already present for this epoch (same key,
        // merged from a rekey slot) keeps its authoritative retired_at.
        let mut k2 = ks();
        let cur = k2.collab_key.clone();
        k2.prior_collab_keys.insert(
            0,
            PriorCollabKey {
                key: cur,
                retired_at: 12345,
            },
        );
        k2.adopt_collab_key("66".repeat(32));
        assert_eq!(k2.prior_collab_keys.get(&0).unwrap().retired_at, 12345);
        // The cap drops the OLDEST epochs first.
        let mut k3 = ks();
        for e in 0..(MAX_PRIOR_COLLAB_KEYS as u32 + 10) {
            k3.epoch = e;
            k3.adopt_collab_key(hex::encode(crypto::random_32()));
        }
        assert_eq!(k3.prior_collab_keys.len(), MAX_PRIOR_COLLAB_KEYS);
        assert!(!k3.prior_collab_keys.contains_key(&0));
    }

    #[test]
    fn retain_knob_off_drops_history_on_roll() {
        let mut k = ks();
        k.adopt_collab_key("44".repeat(32));
        assert_eq!(k.prior_collab_keys.len(), 1);
        k.retain_collab_history = false;
        k.epoch = 1;
        k.adopt_collab_key("55".repeat(32));
        assert!(k.prior_collab_keys.is_empty());
        assert_eq!(k.collab_key_ring().unwrap().len(), 1);
    }

    #[test]
    fn pre_ring_keystore_json_still_loads() {
        // On-disk keystores from before GitLab #21 carry neither the ring
        // nor the knob — they must load with an empty ring and retention ON.
        let mut k = ks();
        k.prior_collab_keys.insert(
            0,
            PriorCollabKey {
                key: "44".repeat(32),
                retired_at: 1,
            },
        );
        let mut v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&k).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("prior_collab_keys");
        v.as_object_mut().unwrap().remove("retain_collab_history");
        let back: Keystore = serde_json::from_value(v).unwrap();
        assert!(back.prior_collab_keys.is_empty());
        assert!(back.retain_collab_history);
    }
}
