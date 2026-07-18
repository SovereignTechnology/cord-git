//! The encrypted manifest: the crown-jewel record mapping git refs to encrypted
//! pack blobs and their per-pack random keys. See design §3.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One encrypted pack blob referenced by the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackEntry {
    /// sha256 of the wire blob (server blob id).
    pub blob_id: String,
    /// 64-hex random ChaCha20-Poly1305 key for this pack.
    pub key: String,
    /// 24-hex random nonce (also embedded in the wire blob; recorded for clarity).
    pub nonce: String,
    /// Wire blob byte length.
    pub size: u64,
}

/// The manifest. Serialized to JSON, then encrypted under the `#state`-derived
/// manifest key and stored as the 30641 `m` blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub v: u32,
    pub community_id: String,
    pub epoch: u32,
    /// refname -> git object id (hex).
    pub refs: BTreeMap<String, String>,
    /// Encrypted packs whose union contains every object reachable from `refs`.
    pub packs: Vec<PackEntry>,
    /// The 30641 event id this manifest supersedes (CAS chain); None for genesis.
    pub manifest_prev: Option<String>,
    pub ts: u64,
}

impl Manifest {
    pub fn genesis(community_id: String, epoch: u32) -> Self {
        Self {
            v: 1,
            community_id,
            epoch,
            refs: BTreeMap::new(),
            packs: Vec::new(),
            manifest_prev: None,
            ts: 0,
        }
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("manifest serializes")
    }

    pub fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}
