//! Construction of the three server-visible event kinds, matching the GRASP-P
//! server contract exactly (see server `src/grasp_p/{registration,state_root,
//! blossom_auth}.rs`).

use anyhow::Result;
use base64::Engine;
use nostr::prelude::FinalizeEvent;
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};

use crate::crypto;
use crate::manifest::PackEntry;

/// Maximum clock-skew tolerance for accepting an event's `created_at` as
/// "not future-dated". Anything newer is rejected: a future-dated event would
/// otherwise win a latest-wins sort indefinitely (pin/rollback attack).
///
/// This is the single source of truth for that bound. It guards the
/// server-visible 30640/30641 editions (`repo.rs`) and, because the same
/// latest-wins shape exists inside the encrypted channels, the `#collab` and
/// guestbook-join inner rumors (`collab.rs`, `invite.rs`).
pub const FUTURE_SLACK_SECS: u64 = 900;

/// Outer wrap kind for every CORD **stream** event — rekeys (`rekey.rs`),
/// `#collab` issues/PRs/comments (`collab.rs`) and guestbook Joins
/// (`invite::build_join`). Signed by a DERIVED key that the live 30640 lists
/// in its `aux` set, so the content-blind node admits it.
///
/// These wraps are NIP-59-*shaped* but deliberately **not NIP-59**: no `p`
/// tag, no kind-13 seal, a symmetric AEAD payload instead of NIP-44, and a
/// derived deterministic signer instead of a one-time random one. Riding kind
/// 1059 would oblige relays to violate NIP-59 in order to serve us, so the
/// stream plane carries its own kind.
///
/// Server counterpart: `ngit-grasp` `src/grasp_p/mod.rs::KIND_STREAM_WRAP`.
/// The server also has `NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND` (on by default)
/// for the legacy kind 1059, but since the port onto ngit-grasp v3 its relay
/// refuses a 1059 without exactly one `p` tag before that setting is
/// consulted, so the tagless stream wraps this client used to emit are no
/// longer accepted. Only 3359 works.
///
/// The ephemeral sibling is 23359 (legacy 21059). This client emits no
/// ephemeral wraps at all, so it has no constant for it.
pub const KIND_STREAM_WRAP: u16 = 3359;

/// Genuine **NIP-59 gift wrap**. Used at exactly two sites — the direct invite
/// (`invite::wrap_invite`) and the promotion whisper (`invite::wrap_promotion`)
/// — both of which are real `GiftWrapBuilder` output: `p`-tagged to the
/// recipient, kind-13 sealed, NIP-44 encrypted, from a FRESH EPHEMERAL signer,
/// and delivered to the recipient's OWN INBOX RELAY, never to a git node.
///
/// **Do not merge this with [`KIND_STREAM_WRAP`].** The two were one constant
/// before the 3359 migration, and re-collapsing them is the easy mistake: the
/// crypto differs, the signer discipline differs, and the transport differs.
/// A stream wrap emitted at 1059 asks relays to break NIP-59; an invite
/// emitted at the stream kind is not a gift wrap at all, and no NIP-59 client
/// would ever open it.
pub const KIND_NIP59_GIFT_WRAP: u16 = 1059;

/// Error text for a wrap whose OUTER kind is not [`KIND_STREAM_WRAP`], shared
/// by the three stream-plane parsers (`collab::parse_collab_with_ring`,
/// `invite::parse_join_with_ring`, `rekey::parse_rekey`).
///
/// [`KIND_NIP59_GIFT_WRAP`] gets its own wording. The person most likely to
/// see it is not an attacker but a member of a repo whose history predates the
/// 3359 migration, holding events this client can no longer read at all; the
/// bare "wrong kind" text tells them nothing about why, or that the age of the
/// event is the reason. Every other kind keeps the generic message.
pub fn unexpected_stream_wrap_kind(kind: u16) -> String {
    if kind == KIND_NIP59_GIFT_WRAP {
        format!(
            "legacy kind-{KIND_NIP59_GIFT_WRAP} stream wrap from before the \
             {KIND_STREAM_WRAP} migration; this client no longer reads it"
        )
    } else {
        format!("not a CORD stream wrap (kind {kind})")
    }
}

/// Current wall-clock seconds since the Unix epoch (0 if the clock predates it).
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a kind-30640 registration, signed by the hosting (tenant) key, with a
/// proof-of-possession on the derived write key and on each aux (stream) key.
/// Aux keys admit stream wraps (guestbook/collab) but can never publish state
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
    build_registration_keysets_at(
        hosting,
        write_keys,
        aux_keys,
        alias,
        relays,
        servers,
        Timestamp::now(),
    )
}

/// created_at-parameterized variant, for TEST/debug tooling only (the e2e
/// squatter: post-!11 the server's §3.2 merge evicts any squat whose
/// created_at is not EARLIER than the live+1 widen, so a squat that should
/// keep wedging rotations must be backdated to win the claim).
#[allow(clippy::too_many_arguments)]
pub fn build_registration_keysets_at(
    hosting: &Keys,
    write_keys: &[&Keys],
    aux_keys: &[&Keys],
    alias: &str,
    relays: &[String],
    servers: &[String],
    created_at: Timestamp,
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
        .custom_created_at(created_at)
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

#[cfg(test)]
mod wrap_kind_tests {
    use super::*;

    /// The wire values, pinned as literals. These are a protocol contract with
    /// the GRASP-P server (`grasp_p/mod.rs`), not an implementation detail:
    /// changing either one silently desynchronises client and node.
    #[test]
    fn wrap_kinds_are_the_wire_values() {
        assert_eq!(KIND_STREAM_WRAP, 3359, "CORD stream wrap kind");
        assert_eq!(KIND_NIP59_GIFT_WRAP, 1059, "NIP-59 gift wrap kind");
    }

    /// The two planes must never collapse back into one constant. They were a
    /// single `KIND_WRAP` before the 3359 migration; re-merging them either
    /// asks relays to serve NIP-59-violating wraps at 1059, or emits invites
    /// at a kind no NIP-59 client will open.
    #[test]
    fn stream_wraps_are_not_nip59_gift_wraps() {
        assert_ne!(
            KIND_STREAM_WRAP, KIND_NIP59_GIFT_WRAP,
            "the stream plane and the NIP-59 invite plane must keep distinct kinds"
        );
    }

    /// A pre-migration wrap must be diagnosed as OLD, not merely as wrong: the
    /// reader who hits it is on a repo whose history predates 3359 and has no
    /// other signal that the kind is why their reads come back empty.
    #[test]
    fn legacy_wrap_kind_is_explained_not_just_rejected() {
        let legacy = unexpected_stream_wrap_kind(KIND_NIP59_GIFT_WRAP);
        assert!(legacy.contains("legacy"), "{legacy}");
        assert!(legacy.contains("1059") && legacy.contains("3359"), "{legacy}");
        assert!(legacy.contains("no longer reads it"), "{legacy}");

        // Any other unexpected kind keeps the generic wording — the legacy
        // explanation must not be handed out for kinds it does not describe.
        let other = unexpected_stream_wrap_kind(1);
        assert_eq!(other, "not a CORD stream wrap (kind 1)");
        let stream_ephemeral = unexpected_stream_wrap_kind(23359);
        assert!(!stream_ephemeral.contains("legacy"), "{stream_ephemeral}");
    }
}
