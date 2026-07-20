//! Per-community keystore on disk under `CORD_GIT_HOME`
//! (default `~/.config/cord-git`). Holds every client secret for one
//! community; the server holds none of this. Files are written 0600 and never
//! logged. See design §5.

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
