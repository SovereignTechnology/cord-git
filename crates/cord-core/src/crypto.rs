//! CORD-git-native crypto primitives.
//!
//! The server is content-blind; these primitives produce the ciphertext and
//! keys the client alone understands. See `docs/grasp-p/phase3-design.md` §2.

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use nostr::secp256k1::{Message, XOnlyPublicKey};
use nostr::{Keys, SecretKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// HKDF label for the per-epoch write keypair derived from `write_secret`.
const WRITE_AUTH_LABEL: &[u8] = b"cord-git/write-auth/v1";
/// HKDF label for the manifest encryption key derived from the `#state` key.
const MANIFEST_LABEL: &[u8] = b"cord-git/manifest/v1";
/// Domain-separation prefix for the self-certifying community id.
const COMMUNITY_LABEL: &[u8] = b"cord-git/community/v1";
/// HKDF label for the derived guestbook STREAM keypair (signs the outer 1059
/// wrap of every guestbook Join — never the member npub). Derived from the
/// shared `#collab` key so every member computes the same keypair.
const GUESTBOOK_STREAM_LABEL: &[u8] = b"cord-git/guestbook-stream/v1";
/// HKDF label for the symmetric guestbook SEAL key (encrypts the Join rumor
/// so only members can read it).
const GUESTBOOK_SEAL_LABEL: &[u8] = b"cord-git/guestbook-seal/v1";
/// HKDF label for the symmetric `#collab` SEAL key (encrypts issue/PR/comment
/// rumors so only channel members can read them). Distinct from the guestbook
/// seal so the two sub-streams are domain-separated even though they share the
/// aux-registered outer stream key.
const COLLAB_SEAL_LABEL: &[u8] = b"cord-git/collab-seal/v1";

/// 32 fresh random bytes from the OS CSPRNG.
pub fn random_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

/// Lowercase hex sha256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Self-certifying community id: sha256(label || owner_xonly(32) || salt(32)).
pub fn community_id(owner: &nostr::PublicKey, salt: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(COMMUNITY_LABEL);
    h.update(owner.to_bytes()); // 32-byte x-only
    h.update(salt);
    hex::encode(h.finalize())
}

/// Derive the per-epoch write keypair from `write_secret`.
///
/// `sk = HKDF-SHA256(salt=WRITE_AUTH_LABEL, ikm=write_secret, info=epoch_le)`,
/// retried into the valid secp256k1 range (astronomically unlikely to loop).
pub fn derive_write_keys(write_secret: &[u8; 32], epoch: u32) -> Result<Keys> {
    let hk = Hkdf::<Sha256>::new(Some(WRITE_AUTH_LABEL), write_secret);
    let mut okm = [0u8; 32];
    let mut info = epoch.to_le_bytes().to_vec();
    for attempt in 0u8..=255 {
        hk.expand(&info, &mut okm)
            .map_err(|_| anyhow!("hkdf expand"))?;
        if let Ok(sk) = SecretKey::from_slice(&okm) {
            return Ok(Keys::new(sk));
        }
        // Reroll the info on the (near-impossible) invalid-scalar case.
        info.push(attempt);
    }
    Err(anyhow!("could not derive a valid write key"))
}

/// Derive the shared guestbook stream keypair from the `#collab` channel key.
/// Every member derives the same keypair; it signs the OUTER wrap of guestbook
/// Joins (the member npub never signs anything server-visible). The pubkey is
/// registered in the 30640 `aux` set so the node admits the wraps.
pub fn derive_guestbook_keys(collab_key: &[u8; 32]) -> Result<Keys> {
    let hk = Hkdf::<Sha256>::new(Some(GUESTBOOK_STREAM_LABEL), collab_key);
    let mut okm = [0u8; 32];
    let mut info: Vec<u8> = Vec::new();
    for attempt in 0u8..=255 {
        hk.expand(&info, &mut okm)
            .map_err(|_| anyhow!("hkdf expand"))?;
        if let Ok(sk) = SecretKey::from_slice(&okm) {
            return Ok(Keys::new(sk));
        }
        info.push(attempt);
    }
    Err(anyhow!("could not derive a valid guestbook key"))
}

/// Symmetric AEAD key sealing guestbook rumors (derived from `#collab`).
pub fn guestbook_seal_key(collab_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(GUESTBOOK_SEAL_LABEL), collab_key);
    let mut out = [0u8; 32];
    hk.expand(&[], &mut out).expect("hkdf 32 bytes is valid");
    out
}

/// Symmetric AEAD key sealing `#collab` issue/PR/comment rumors (derived from
/// the `#collab` channel key). Rolls with `collab_key` on every refounding, so
/// a revoked member holding the old key cannot read post-rotation content.
pub fn collab_seal_key(collab_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(COLLAB_SEAL_LABEL), collab_key);
    let mut out = [0u8; 32];
    hk.expand(&[], &mut out).expect("hkdf 32 bytes is valid");
    out
}

/// Seal `plaintext` under a shared symmetric key with a FRESH random nonce
/// (wire = nonce(12) || ct||tag — same framing as blobs/manifests).
pub fn seal_symmetric(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    seal(key, &nonce, plaintext)
}

/// Open a `seal_symmetric` wire blob.
pub fn open_symmetric(key: &[u8; 32], wire: &[u8]) -> Result<Vec<u8>> {
    open(key, wire)
}

/// Schnorr proof-of-possession for a claimed write/aux key, matching the
/// server's `verify_key_pop`: schnorr over sha256("grasp-p key-claim:<tenant>:
/// <alias>") by the claimed key. Returns the 128-hex signature.
pub fn key_pop_sig(write_keys: &Keys, tenant_hex: &str, alias: &str) -> String {
    let preimage = format!("grasp-p key-claim:{tenant_hex}:{alias}");
    let digest = Sha256::digest(preimage.as_bytes());
    let msg = Message::from_digest(digest.into());
    let sig = write_keys.sign_schnorr(&msg);
    sig.to_string()
}

/// Verify a proof-of-possession (used in tests to match the server).
pub fn verify_key_pop(key_hex: &str, sig_hex: &str, tenant_hex: &str, alias: &str) -> bool {
    use std::str::FromStr;
    let Ok(pk) = XOnlyPublicKey::from_str(key_hex) else {
        return false;
    };
    let Ok(sig) = nostr::secp256k1::schnorr::Signature::from_str(sig_hex) else {
        return false;
    };
    let preimage = format!("grasp-p key-claim:{tenant_hex}:{alias}");
    let digest = Sha256::digest(preimage.as_bytes());
    let msg = Message::from_digest(digest.into());
    nostr::SECP256K1.verify_schnorr(&sig, &msg, &pk).is_ok()
}

/// Wire form of an encrypted blob: `nonce(12) || ciphertext||tag`.
/// `blob_id = sha256(wire)` — matches the server's `sha256(bytes-you-PUT)`.
pub struct EncryptedBlob {
    pub wire: Vec<u8>,
    pub blob_id: String,
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

/// Encrypt a blob (pack) under a FRESH random 32-byte key + random 12-byte
/// nonce (never convergent). The random key is recorded in the manifest.
pub fn encrypt_blob_random(plaintext: &[u8]) -> Result<EncryptedBlob> {
    let key = random_32();
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let wire = seal(&key, &nonce, plaintext)?;
    let blob_id = sha256_hex(&wire);
    Ok(EncryptedBlob {
        wire,
        blob_id,
        key,
        nonce,
    })
}

/// Encrypt the manifest under a key derived from the `#state` channel key
/// (any channel member can read it); random nonce, prepended.
pub fn encrypt_manifest(state_key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedBlob> {
    let key = manifest_key(state_key);
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let wire = seal(&key, &nonce, plaintext)?;
    let blob_id = sha256_hex(&wire);
    Ok(EncryptedBlob {
        wire,
        blob_id,
        key,
        nonce,
    })
}

/// Decrypt a manifest blob fetched by its `m` hash using the `#state` key.
pub fn decrypt_manifest(state_key: &[u8; 32], wire: &[u8]) -> Result<Vec<u8>> {
    open(&manifest_key(state_key), wire)
}

/// Decrypt a pack blob given its recorded random key.
pub fn decrypt_blob(key: &[u8; 32], wire: &[u8]) -> Result<Vec<u8>> {
    open(key, wire)
}

fn manifest_key(state_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(MANIFEST_LABEL), state_key);
    let mut out = [0u8; 32];
    hk.expand(&[], &mut out).expect("hkdf 32 bytes is valid");
    out
}

fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| anyhow!("aead seal"))?;
    let mut wire = Vec::with_capacity(12 + ct.len());
    wire.extend_from_slice(nonce);
    wire.extend_from_slice(&ct);
    Ok(wire)
}

fn open(key: &[u8; 32], wire: &[u8]) -> Result<Vec<u8>> {
    if wire.len() < 12 {
        return Err(anyhow!("blob too short for nonce"));
    }
    let (nonce, ct) = wire.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| anyhow!("aead open (wrong key or tampered ciphertext)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_key_derivation_is_deterministic() {
        let secret = [7u8; 32];
        let a = derive_write_keys(&secret, 0).unwrap();
        let b = derive_write_keys(&secret, 0).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        // Different epoch → different key.
        let c = derive_write_keys(&secret, 1).unwrap();
        assert_ne!(a.public_key(), c.public_key());
    }

    #[test]
    fn pop_roundtrip_matches_server_rule() {
        let secret = [3u8; 32];
        let wk = derive_write_keys(&secret, 0).unwrap();
        let tenant = "aa".repeat(32);
        let alias = "bb".repeat(16);
        let sig = key_pop_sig(&wk, &tenant, &alias);
        assert_eq!(sig.len(), 128);
        assert!(verify_key_pop(
            &wk.public_key().to_hex(),
            &sig,
            &tenant,
            &alias
        ));
        // Wrong alias must not verify (binding to tenant/alias).
        assert!(!verify_key_pop(&wk.public_key().to_hex(), &sig, &tenant, "cc"));
    }

    #[test]
    fn blob_random_key_roundtrip_and_unique_nonce() {
        let pt = b"a git pack payload".to_vec();
        let a = encrypt_blob_random(&pt).unwrap();
        let b = encrypt_blob_random(&pt).unwrap();
        // Fresh key + nonce each time → different ciphertext, no convergence.
        assert_ne!(a.wire, b.wire);
        assert_ne!(a.key, b.key);
        assert_ne!(a.nonce, b.nonce);
        assert_eq!(decrypt_blob(&a.key, &a.wire).unwrap(), pt);
        assert_eq!(a.blob_id, sha256_hex(&a.wire));
        // Wrong key fails (AEAD tag).
        assert!(decrypt_blob(&b.key, &a.wire).is_err());
    }

    #[test]
    fn manifest_roundtrip_under_state_key() {
        let state = [9u8; 32];
        let pt = b"{\"refs\":{}}".to_vec();
        let enc = encrypt_manifest(&state, &pt).unwrap();
        assert_eq!(decrypt_manifest(&state, &enc.wire).unwrap(), pt);
        // A different state key cannot read it.
        assert!(decrypt_manifest(&[1u8; 32], &enc.wire).is_err());
    }
}
