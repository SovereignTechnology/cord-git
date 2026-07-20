//! Construction of the three server-visible event kinds, matching the GRASP-P
//! server contract exactly (see server `src/private/{registration,state_root,
//! blossom_auth}.rs`).

use anyhow::Result;
use base64::Engine;
use nostr::prelude::FinalizeEvent;
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};

use crate::crypto;
use crate::manifest::PackEntry;

/// Build a kind-30640 registration, signed by the hosting (tenant) key, with a
/// proof-of-possession on the derived write key and on each aux (stream) key.
/// Aux keys admit 1059 wraps (guestbook/collab) but can never publish state
/// roots or blobs — the server enforces the role split.
pub fn build_registration(
    hosting: &Keys,
    write_keys: &Keys,
    aux_keys: &[&Keys],
    alias: &str,
    relays: &[String],
    servers: &[String],
) -> Result<nostr::Event> {
    build_registration_keysets(hosting, &[write_keys], aux_keys, alias, relays, servers)
}

/// Multi-key registration variant used by the §3.3 rotation sequencing
/// (30640′ widen lists w = old ∪ new and aux = old ∪ new ∪ rekey addresses;
/// 30640″ narrow lists the new-only sets). Every listed key carries a PoP.
pub fn build_registration_keysets(
    hosting: &Keys,
    write_keys: &[&Keys],
    aux_keys: &[&Keys],
    alias: &str,
    relays: &[String],
    servers: &[String],
) -> Result<nostr::Event> {
    let tenant_hex = hosting.public_key().to_hex();
    let mut tags = vec![Tag::identifier(alias.to_string())];
    for w in write_keys {
        let pop = crypto::key_pop_sig(w, &tenant_hex, alias);
        tags.push(Tag::custom("w", vec![w.public_key().to_hex(), pop]));
    }
    for aux in aux_keys {
        let aux_pop = crypto::key_pop_sig(aux, &tenant_hex, alias);
        tags.push(Tag::custom(
            "aux",
            vec![aux.public_key().to_hex(), aux_pop],
        ));
    }
    tags.push(Tag::custom("relays", relays.to_vec()));
    tags.push(Tag::custom("server", servers.to_vec()));
    tags.shrink_to_fit();
    Ok(EventBuilder::new(Kind::Custom(30640), "")
        .tags(tags)
        .finalize(hosting)?)
}

/// Build a kind-30641 state root, signed by a registered write key.
pub fn build_state_root(
    write_keys: &Keys,
    tenant_hex: &str,
    alias: &str,
    manifest_blob_id: &str,
    manifest_size: u64,
    packs: &[PackEntry],
) -> Result<nostr::Event> {
    let coord = format!("30640:{tenant_hex}:{alias}");
    let mut tags = vec![
        Tag::identifier(alias.to_string()),
        Tag::custom("a", vec![coord]),
        Tag::custom(
            "m",
            vec![manifest_blob_id.to_string(), manifest_size.to_string()],
        ),
    ];
    for p in packs {
        tags.push(Tag::custom(
            "pack",
            vec![p.blob_id.clone(), p.size.to_string()],
        ));
    }
    Ok(EventBuilder::new(Kind::Custom(30641), "")
        .tags(tags)
        .finalize(write_keys)?)
}

/// Blossom operation.
#[derive(Debug, Clone, Copy)]
pub enum BlobOp {
    Upload,
    Delete,
}

impl BlobOp {
    fn tag_value(self) -> &'static str {
        match self {
            BlobOp::Upload => "upload",
            BlobOp::Delete => "delete",
        }
    }
}

/// Build a kind-24242 Blossom authorization event + the `Authorization` header
/// value (`Nostr <base64(event-json)>`), signed by a registered write key.
pub fn build_blossom_auth(
    write_keys: &Keys,
    op: BlobOp,
    sha256_hex: &str,
    tenant_hex: &str,
    alias: &str,
) -> Result<(nostr::Event, String)> {
    let expiration = Timestamp::now().as_secs() + 3600;
    let coord = format!("30640:{tenant_hex}:{alias}");
    let tags = vec![
        Tag::custom("t", vec![op.tag_value().to_string()]),
        Tag::custom("x", vec![sha256_hex.to_string()]),
        Tag::custom(
            "expiration",
            vec![expiration.to_string()],
        ),
        Tag::custom("a", vec![coord]),
    ];
    let event = EventBuilder::new(Kind::Custom(24242), "")
        .tags(tags)
        .finalize(write_keys)?;
    let header = format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(event.as_json())
    );
    Ok((event, header))
}
