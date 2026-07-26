//! `#collab` issues/PRs/comments as SIGNED NIP-34/22/32 rumors (plan §2, §3.2;
//! GitLab issue !2).
//!
//! Wire model (three layers, outermost first):
//!
//! 1. **Outer wrap** — kind-1059, signed by the derived `#collab` stream key
//!    (`Keystore::guestbook_keys`, registered in the 30640 `aux` set so the
//!    content-blind node admits it). Its `created_at` is tweaked into the past
//!    (NIP-59 metadata-privacy discipline); rendering uses the INNER timestamp.
//! 2. **20013 seal** — realized as a symmetric AEAD envelope under the
//!    `#collab`-derived seal key (`crypto::collab_seal_key`), fresh nonce each
//!    time. The seal kind is 20013 (Concord's addressable seal) conceptually;
//!    on the content-blind node it can only travel inside the admitted 1059
//!    outer, so the seal here is the encryption layer, not a separate stored
//!    event. Its bytes are the base64 content of the outer wrap.
//! 3. **Inner rumor** — a LITERAL NIP-34/22/32 kind (1621 issue, 1111 comment,
//!    1617 patch, 1630-1633 status), SIGNED by the author's own identity key.
//!    Its raw JSON bytes are retained verbatim on disk so a future flip-public
//!    can republish them with ids/threading/signatures intact.
//!
//! **Rumor binding (plan §2, MANDATED tags — NOT the native `cgc` tag):** every
//! inner rumor carries `a` = `30617:<tenant>:cg-<community_id>` (the eventual
//! public-30617 coordinate; `<tenant>` = hosting pseudonym), a `channel` tag
//! (`collab`), and an `epoch` tag. The a-tag binds against cross-repo replay;
//! readers reject an a-tag or channel mismatch outright, and reject an `epoch`
//! tag that claims a FUTURE epoch. Content from before a refounding is already
//! unreadable because the `#collab` key (hence the seal key) rolled — so the
//! epoch tag stays permissive across demotes (which bump the global epoch
//! without rekeying `#collab`) while the crypto enforces the refounding cliff.
//!
//! NOTE — divergence from the invite/join stage: that stage bound its guestbook
//! Join rumor with a native `cgc` tag. Per plan §2 this stage uses the mandated
//! `channel`/`epoch` tags instead. The two sub-streams share the aux-registered
//! outer stream key but use distinct seal keys and distinct binding conventions;
//! the review stage should reconcile the guestbook Join onto channel/epoch tags.

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use nostr::prelude::FinalizeEvent;
use nostr::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};

use crate::crypto;
use crate::events::FUTURE_SLACK_SECS;
use crate::keystore::Keystore;

/// NIP-34 issue.
pub const KIND_ISSUE: u16 = 1621;
/// NIP-22 comment (threading via `e`-tags).
pub const KIND_COMMENT: u16 = 1111;
/// NIP-34 patch (one per commit in a series).
pub const KIND_PATCH: u16 = 1617;
/// NIP-34 status: open.
pub const KIND_STATUS_OPEN: u16 = 1630;
/// NIP-34 status: applied/merged.
pub const KIND_STATUS_APPLIED: u16 = 1631;
/// NIP-34 status: closed.
pub const KIND_STATUS_CLOSED: u16 = 1632;
/// NIP-34 status: draft.
pub const KIND_STATUS_DRAFT: u16 = 1633;
/// Concord addressable seal kind (see module docs — realized as the AEAD layer).
pub const KIND_SEAL: u16 = 20013;
/// Admitted outer wrap kind.
pub const KIND_WRAP: u16 = 1059;

/// The mandated `channel` tag value for this data plane.
const CHANNEL_COLLAB: &str = "collab";

/// The set of inner rumor kinds this stream understands.
fn is_collab_kind(kind: u16) -> bool {
    matches!(
        kind,
        KIND_ISSUE
            | KIND_COMMENT
            | KIND_PATCH
            | KIND_STATUS_OPEN
            | KIND_STATUS_APPLIED
            | KIND_STATUS_CLOSED
            | KIND_STATUS_DRAFT
    )
}

/// A thread status a writer can set on an issue or PR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Open,
    Merged,
    Closed,
    Draft,
}

impl Status {
    pub fn kind(self) -> u16 {
        match self {
            Status::Open => KIND_STATUS_OPEN,
            Status::Merged => KIND_STATUS_APPLIED,
            Status::Closed => KIND_STATUS_CLOSED,
            Status::Draft => KIND_STATUS_DRAFT,
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "open" => Status::Open,
            "merged" | "applied" => Status::Merged,
            "closed" => Status::Closed,
            "draft" => Status::Draft,
            other => bail!("unknown status '{other}' (use open|merged|closed|draft)"),
        })
    }
    /// Human label for a status KIND (1630-1633); `None` if not a status kind.
    pub fn label(kind: u16) -> Option<&'static str> {
        match kind {
            KIND_STATUS_OPEN => Some("open"),
            KIND_STATUS_APPLIED => Some("merged"),
            KIND_STATUS_CLOSED => Some("closed"),
            KIND_STATUS_DRAFT => Some("draft"),
            _ => None,
        }
    }
}

/// A built `#collab` message ready to publish: the outer wrap plus the verbatim
/// inner-rumor bytes the caller must retain (flip-public byte-exact republish).
pub struct CollabPublish {
    /// Outer kind-1059 wrap (server-visible).
    pub wrap: Event,
    /// Raw signed inner rumor JSON — retain on disk verbatim.
    pub raw: Vec<u8>,
    /// Inner rumor id (thread anchor).
    pub rumor_id: String,
}

/// The `a`-tag coordinate a rumor binds to: `30617:<tenant>:cg-<community_id>`.
fn a_coord(ks: &Keystore) -> Result<String> {
    Ok(format!("30617:{}:cg-{}", ks.tenant_hex()?, ks.community_id))
}

/// Mandated binding tags every inner rumor carries (plan §2).
fn binding_tags(ks: &Keystore) -> Result<Vec<Tag>> {
    Ok(vec![
        Tag::custom("a", vec![a_coord(ks)?]),
        Tag::custom("channel", vec![CHANNEL_COLLAB.to_string()]),
        Tag::custom("epoch", vec![ks.epoch.to_string()]),
    ])
}

/// Seal a signed inner rumor into an admitted outer wrap. Shared by every
/// builder. `extra` are the kind-specific tags (subject, e-threading, …).
fn seal_rumor(
    author: &Keys,
    ks: &Keystore,
    kind: u16,
    content: &str,
    extra: Vec<Tag>,
) -> Result<CollabPublish> {
    let mut tags = binding_tags(ks)?;
    tags.extend(extra);
    // Inner rumor: a REAL signed event by the author identity. Its raw bytes
    // are retained verbatim (re-serialization would drift the id/signature).
    let rumor = EventBuilder::new(Kind::Custom(kind), content)
        .tags(tags)
        .finalize(author)?;
    let raw = rumor.as_json().into_bytes();

    // 20013 seal: symmetric AEAD under the #collab seal key (fresh nonce).
    let seal_key = crypto::collab_seal_key(&ks.collab_key_bytes()?);
    let sealed = crypto::seal_symmetric(&seal_key, &raw)?;
    let wrap_content = base64::engine::general_purpose::STANDARD.encode(sealed);

    // Outer 1059: derived #collab stream key (aux-registered); past-tweaked ts.
    let stream = ks.guestbook_keys()?;
    let wrap = EventBuilder::new(Kind::Custom(KIND_WRAP), wrap_content)
        .custom_created_at(Timestamp::tweaked(0..172_800))
        .finalize(&stream)?;
    Ok(CollabPublish {
        wrap,
        raw,
        rumor_id: rumor.id.to_hex(),
    })
}

/// Build a new issue (thread root).
pub fn build_issue(author: &Keys, ks: &Keystore, subject: &str, body: &str) -> Result<CollabPublish> {
    if subject.trim().is_empty() {
        bail!("issue subject must not be empty");
    }
    let extra = vec![Tag::custom("subject", vec![subject.to_string()])];
    seal_rumor(author, ks, KIND_ISSUE, body, extra)
}

/// Build a comment on `root_id` (an issue or PR). `parent_id` (if different
/// from the root) records the direct reply target.
pub fn build_comment(
    author: &Keys,
    ks: &Keystore,
    root_id: &str,
    parent_id: Option<&str>,
    body: &str,
) -> Result<CollabPublish> {
    if !is_event_id(root_id) {
        bail!("invalid root id (expected 64 lowercase hex)");
    }
    let mut extra = vec![Tag::custom("e", vec![root_id.to_string(), String::new(), "root".to_string()])];
    if let Some(p) = parent_id {
        if p != root_id {
            if !is_event_id(p) {
                bail!("invalid reply id (expected 64 lowercase hex)");
            }
            extra.push(Tag::custom("e", vec![p.to_string(), String::new(), "reply".to_string()]));
        }
    }
    seal_rumor(author, ks, KIND_COMMENT, body, extra)
}

/// Build a status update (open/merged/closed/draft) on `root_id`.
pub fn build_status(
    author: &Keys,
    ks: &Keystore,
    root_id: &str,
    status: Status,
    note: &str,
) -> Result<CollabPublish> {
    if !is_event_id(root_id) {
        bail!("invalid target id (expected 64 lowercase hex)");
    }
    let extra = vec![Tag::custom("e", vec![root_id.to_string(), String::new(), "root".to_string()])];
    seal_rumor(author, ks, status.kind(), note, extra)
}

/// Build one patch in a series. The FIRST patch of a PR passes `thread_root =
/// None` (it becomes the root, marked with a `t=root` tag); subsequent patches
/// pass the root's rumor id so they thread under it.
pub fn build_patch(
    author: &Keys,
    ks: &Keystore,
    thread_root: Option<&str>,
    subject: &str,
    patch: &str,
) -> Result<CollabPublish> {
    let mut extra = vec![Tag::custom("subject", vec![subject.to_string()])];
    match thread_root {
        None => extra.push(Tag::custom("t", vec!["root".to_string()])),
        Some(root_id) => {
            if !is_event_id(root_id) {
                bail!("invalid PR root id (expected 64 lowercase hex)");
            }
            extra.push(Tag::custom(
                "e",
                vec![root_id.to_string(), String::new(), "root".to_string()],
            ));
        }
    }
    seal_rumor(author, ks, KIND_PATCH, patch, extra)
}

/// A parsed `#collab` inner rumor (after full verification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollabEvent {
    pub id: String,
    pub author: String,
    pub kind: u16,
    pub created_at: u64,
    pub content: String,
    /// `subject` tag (issues / patch roots).
    pub subject: Option<String>,
    /// Root e-tag target (children of a thread); `None` for a root.
    pub root: Option<String>,
    /// Direct reply e-tag target, if any.
    pub reply: Option<String>,
}

impl CollabEvent {
    pub fn is_root(&self) -> bool {
        self.root.is_none() && (self.kind == KIND_ISSUE || self.kind == KIND_PATCH)
    }
}

fn is_event_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn tag_vec(t: &Tag) -> Vec<String> {
    t.clone().to_vec()
}

/// Verify + open one outer wrap into a `CollabEvent`. Rejects: bad outer/inner
/// signatures; wraps not signed by THIS community's derived stream key; wraps
/// that do not decrypt under the current `#collab` seal key (wrong epoch / not a
/// member); non-collab inner kinds; and rumors whose `a`/`channel`/`epoch`
/// binding does not match this community and epoch (cross-repo / cross-epoch
/// replay).
pub fn parse_collab(ks: &Keystore, wrap: &Event) -> Result<CollabEvent> {
    parse_collab_at(ks, wrap, crate::events::now_secs())
}

/// [`parse_collab`] with an explicit wall clock, so the future-dating bound is
/// testable without sleeping. `now` is seconds since the Unix epoch.
pub fn parse_collab_at(ks: &Keystore, wrap: &Event, now: u64) -> Result<CollabEvent> {
    wrap.verify()
        .map_err(|e| anyhow!("collab wrap has an invalid signature: {e}"))?;
    if wrap.kind != Kind::Custom(KIND_WRAP) {
        bail!("not a 1059 wrap");
    }
    let stream = ks.guestbook_keys()?;
    if wrap.pubkey != stream.public_key() {
        bail!("wrap outer signer is not the derived #collab stream key");
    }
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(wrap.content.as_bytes())
        .map_err(|_| anyhow!("collab wrap content is not base64"))?;
    let seal_key = crypto::collab_seal_key(&ks.collab_key_bytes()?);
    let raw = crypto::open_symmetric(&seal_key, &sealed)?;
    let inner = Event::from_json(String::from_utf8_lossy(&raw).as_ref())
        .map_err(|e| anyhow!("sealed collab payload is not an event: {e}"))?;
    inner
        .verify()
        .map_err(|e| anyhow!("inner collab rumor has an invalid signature: {e}"))?;
    let kind = inner.kind.as_u16();
    if !is_collab_kind(kind) {
        bail!("sealed rumor is not a #collab kind (kind {kind})");
    }
    // A future-dated rumor sorts after every honest one forever, so any member
    // — read-only included, since they hold the #collab key — could otherwise
    // pin a thread's displayed status permanently (`fold_threads` takes the
    // largest created_at). Bound it exactly as the 30640/30641 editions are.
    // Only the INNER rumor is bounded: the outer wrap is deliberately
    // past-tweaked for metadata privacy.
    if inner.created_at.as_secs() > now.saturating_add(FUTURE_SLACK_SECS) {
        bail!("collab rumor is future-dated beyond {FUTURE_SLACK_SECS}s of slack (status-pin rejected)");
    }

    // Mandated binding checks (plan §2): a-tag community coordinate + channel +
    // epoch. These are what stop cross-repo and cross-epoch replay.
    let want_a = a_coord(ks)?;
    let mut a_ok = false;
    let mut channel_ok = false;
    let mut epoch_ok = false;
    let mut subject = None;
    let mut root = None;
    let mut reply = None;
    for t in inner.tags.iter() {
        let v = tag_vec(t);
        if v.is_empty() {
            continue;
        }
        match v[0].as_str() {
            "a" if v.len() >= 2 => a_ok = v[1] == want_a,
            "channel" if v.len() >= 2 => channel_ok = v[1] == CHANNEL_COLLAB,
            // Accept this epoch and any PRIOR one under the SAME #collab key: a
            // demote bumps the global epoch without rekeying #collab, so its
            // pre-demote history must stay readable. Content from before a
            // REFOUNDING is already unreadable (the collab key rolled, so the
            // seal key above fails to decrypt). A tag claiming a FUTURE epoch is
            // a cross-epoch replay/forgery signal and is rejected.
            "epoch" if v.len() >= 2 => {
                epoch_ok = v[1].parse::<u32>().map(|e| e <= ks.epoch).unwrap_or(false);
            }
            "subject" if v.len() >= 2 && subject.is_none() => subject = Some(v[1].clone()),
            "e" if v.len() >= 2 => {
                let marker = v.get(3).map(|s| s.as_str()).unwrap_or("");
                if marker == "reply" {
                    reply = Some(v[1].clone());
                } else if root.is_none() {
                    // "root" marker, or an unmarked e-tag → treat as the root.
                    root = Some(v[1].clone());
                }
            }
            _ => {}
        }
    }
    if !a_ok {
        bail!("collab rumor a-tag does not bind this community (cross-repo replay rejected)");
    }
    if !channel_ok {
        bail!("collab rumor is not bound to the #collab channel");
    }
    if !epoch_ok {
        bail!("collab rumor epoch tag is missing or claims a future epoch (cross-epoch replay rejected)");
    }
    Ok(CollabEvent {
        id: inner.id.to_hex(),
        author: inner.pubkey.to_hex(),
        kind,
        created_at: inner.created_at.as_secs(),
        content: inner.content.clone(),
        subject,
        root,
        reply,
    })
}

/// A folded thread: a root (issue or PR) plus its chronological children
/// (comments + status updates) and the latest status seen.
#[derive(Debug, Clone)]
pub struct Thread {
    pub root: CollabEvent,
    pub children: Vec<CollabEvent>,
    /// Latest status kind observed on this thread (by inner timestamp).
    pub latest_status: Option<u16>,
}

impl Thread {
    /// Convenience: the latest status as a human label, or "open" by default.
    pub fn status_label(&self) -> &'static str {
        self.latest_status
            .and_then(Status::label)
            .unwrap_or("open")
    }
}

/// Fold a verified event set into threads. Roots are issues / patch-series
/// roots; every other event attaches to its `root` e-tag target. Children are
/// sorted chronologically; a stray child whose root is absent is dropped.
pub fn fold_threads(mut events: Vec<CollabEvent>) -> Vec<Thread> {
    // Deterministic order: chronological, id tiebreak.
    events.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));

    let mut threads: Vec<Thread> = Vec::new();
    let mut idx: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    // Pass 1: roots.
    for ev in events.iter().filter(|e| e.is_root()) {
        idx.insert(ev.id.clone(), threads.len());
        threads.push(Thread {
            root: ev.clone(),
            children: Vec::new(),
            latest_status: None,
        });
    }
    // Pass 2: children (comments, statuses, non-root patches).
    for ev in events.iter().filter(|e| !e.is_root()) {
        let Some(root_id) = ev.root.clone() else {
            continue;
        };
        if let Some(&ti) = idx.get(&root_id) {
            if Status::label(ev.kind).is_some() {
                threads[ti].latest_status = Some(ev.kind);
            }
            threads[ti].children.push(ev.clone());
        }
    }
    // Newest thread first (by root time).
    threads.sort_by(|a, b| {
        b.root
            .created_at
            .cmp(&a.root.created_at)
            .then(a.root.id.cmp(&b.root.id))
    });
    threads
}

/// Fetch + parse every readable `#collab` message for a community, keeping only
/// events that verify and bind to this community/epoch. Best-effort: individual
/// unreadable wraps (foreign, wrong-epoch, tampered) are skipped, not fatal.
///
/// READABILITY BOUNDARY: the outer stream key and seal key are derived from the
/// CURRENT `#collab` key, which rolls on every refounding (revoke). So this only
/// ever returns messages published since the most recent rekey — history before
/// a rotation is intentionally unreadable with the current keys.
pub fn read_all(ks: &Keystore, wraps: &[Event]) -> Vec<CollabEvent> {
    read_all_at(ks, wraps, crate::events::now_secs())
}

/// [`read_all`] with an explicit wall clock. The clock is sampled once by the
/// caller so every wrap in a batch is judged against the same instant.
pub fn read_all_at(ks: &Keystore, wraps: &[Event], now: u64) -> Vec<CollabEvent> {
    let mut out = Vec::new();
    for w in wraps {
        if let Ok(ev) = parse_collab_at(ks, w, now) {
            out.push(ev);
        }
    }
    // Dedup by id (a relay may serve the same wrap twice).
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out.dedup_by(|a, b| a.id == b.id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::Role;

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
    fn issue_roundtrip_binds_and_retains_raw() {
        let ks = owner_keystore();
        let author = Keys::generate();
        let pubbed = build_issue(&author, &ks, "fix the bug", "it crashes on empty input").unwrap();

        // Outer signer is the derived stream key, never the author npub; no
        // plaintext leaks onto the wire.
        assert_eq!(pubbed.wrap.pubkey, ks.guestbook_keys().unwrap().public_key());
        assert_ne!(pubbed.wrap.pubkey, author.public_key());
        assert!(!pubbed.wrap.as_json().contains("fix the bug"));
        assert!(!pubbed.wrap.as_json().contains(&ks.community_id));

        // Retained raw bytes parse + verify standalone (flip discipline).
        let inner = Event::from_json(String::from_utf8(pubbed.raw.clone()).unwrap()).unwrap();
        inner.verify().unwrap();
        assert_eq!(inner.id.to_hex(), pubbed.rumor_id);

        let ev = parse_collab(&ks, &pubbed.wrap).unwrap();
        assert_eq!(ev.kind, KIND_ISSUE);
        assert_eq!(ev.subject.as_deref(), Some("fix the bug"));
        assert_eq!(ev.content, "it crashes on empty input");
        assert_eq!(ev.author, author.public_key().to_hex());
        assert!(ev.is_root());
    }

    #[test]
    fn non_member_and_cross_repo_are_rejected() {
        let ks = owner_keystore();
        let author = Keys::generate();
        let pubbed = build_issue(&author, &ks, "s", "b").unwrap();

        // Wrong #collab key (revoked / non-member) cannot open it.
        let mut other = ks.clone();
        other.collab_key = hex::encode(crypto::random_32());
        assert!(parse_collab(&other, &pubbed.wrap).is_err());

        // Same stream+seal key but a DIFFERENT community id → a-tag mismatch.
        // (Simulate by building under ks then reading under a keystore with the
        // same collab_key but a foreign community id/tenant.)
        let mut foreign = ks.clone();
        foreign.community_id = "cd".repeat(32);
        assert!(parse_collab(&foreign, &pubbed.wrap).is_err());
    }

    #[test]
    fn epoch_binding_rejects_future_but_allows_historical() {
        let mut ks = owner_keystore();
        ks.epoch = 5;
        let author = Keys::generate();
        let pubbed = build_issue(&author, &ks, "s", "b").unwrap(); // tagged epoch 5

        // A reader at an EARLIER epoch rejects a future-epoch (5) rumor.
        let mut earlier = ks.clone();
        earlier.epoch = 2;
        assert!(parse_collab(&earlier, &pubbed.wrap).is_err());

        // A LATER epoch with the SAME #collab key still reads it — a demote
        // bumps the global epoch without rekeying #collab, so pre-demote
        // history stays readable.
        let mut later = ks.clone();
        later.epoch = 7;
        assert!(parse_collab(&later, &pubbed.wrap).is_ok());
    }

    #[test]
    fn threading_folds_comments_and_status() {
        let ks = owner_keystore();
        let a = Keys::generate();
        let b = Keys::generate();

        let issue = build_issue(&a, &ks, "leak in parser", "steps to repro...").unwrap();
        let root_id = issue.rumor_id.clone();
        let c1 = build_comment(&b, &ks, &root_id, None, "confirmed on my box").unwrap();
        let c1_id = c1.rumor_id.clone();
        let c2 = build_comment(&a, &ks, &root_id, Some(&c1_id), "patch incoming").unwrap();
        let closed = build_status(&a, &ks, &root_id, Status::Closed, "fixed in HEAD").unwrap();

        let wraps: Vec<Event> = vec![issue.wrap, c1.wrap, c2.wrap, closed.wrap];
        let evs = read_all(&ks, &wraps);
        assert_eq!(evs.len(), 4);
        let threads = fold_threads(evs);
        assert_eq!(threads.len(), 1);
        let t = &threads[0];
        assert_eq!(t.root.id, root_id);
        assert_eq!(t.children.len(), 3);
        assert_eq!(t.status_label(), "closed");
        // The reply marker was captured on the second comment.
        assert!(t.children.iter().any(|c| c.reply.as_deref() == Some(c1_id.as_str())));
    }

    #[test]
    fn patch_series_roots_and_threads() {
        let ks = owner_keystore();
        let a = Keys::generate();
        let p0 = build_patch(&a, &ks, None, "[PATCH 1/2] first", "diff0").unwrap();
        let root_id = p0.rumor_id.clone();
        let p1 = build_patch(&a, &ks, Some(&root_id), "[PATCH 2/2] second", "diff1").unwrap();
        let merged = build_status(&a, &ks, &root_id, Status::Merged, "applied").unwrap();

        let wraps = vec![p0.wrap, p1.wrap, merged.wrap];
        let threads = fold_threads(read_all(&ks, &wraps));
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].root.kind, KIND_PATCH);
        assert_eq!(threads[0].root.id, root_id);
        assert_eq!(threads[0].children.len(), 2);
        assert_eq!(threads[0].status_label(), "merged");
    }

    /// Seal a rumor with an attacker-chosen `created_at`. Mirrors `seal_rumor`
    /// exactly except for the inner timestamp — this is what a member with the
    /// `#collab` key can trivially produce.
    fn seal_rumor_dated(
        author: &Keys,
        ks: &Keystore,
        kind: u16,
        content: &str,
        extra: Vec<Tag>,
        created: u64,
    ) -> Event {
        let mut tags = binding_tags(ks).unwrap();
        tags.extend(extra);
        let rumor = EventBuilder::new(Kind::Custom(kind), content)
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(created))
            .finalize(author)
            .unwrap();
        let seal_key = crypto::collab_seal_key(&ks.collab_key_bytes().unwrap());
        let sealed = crypto::seal_symmetric(&seal_key, &rumor.as_json().into_bytes()).unwrap();
        let content_b64 = base64::engine::general_purpose::STANDARD.encode(sealed);
        EventBuilder::new(Kind::Custom(KIND_WRAP), content_b64)
            .custom_created_at(Timestamp::tweaked(0..172_800))
            .finalize(&ks.guestbook_keys().unwrap())
            .unwrap()
    }

    #[test]
    fn future_dated_inner_rumor_is_rejected_but_slack_is_allowed() {
        let ks = owner_keystore();
        let author = Keys::generate();
        let now = crate::events::now_secs();
        let extra = vec![Tag::custom("subject", vec!["s".to_string()])];

        // Inside the slack window: accepted (clock skew must not break members).
        let ok = seal_rumor_dated(&author, &ks, KIND_ISSUE, "b", extra.clone(), now + FUTURE_SLACK_SECS - 60);
        assert!(parse_collab_at(&ks, &ok, now).is_ok());

        // Just past the slack window: rejected.
        let over = seal_rumor_dated(&author, &ks, KIND_ISSUE, "b", extra.clone(), now + FUTURE_SLACK_SECS + 60);
        assert!(parse_collab_at(&ks, &over, now).is_err());

        // The issue-15/16 attack shape: created_at = now + 10 years.
        let far = seal_rumor_dated(&author, &ks, KIND_ISSUE, "b", extra, now + 10 * 365 * 86_400);
        let err = parse_collab_at(&ks, &far, now).unwrap_err().to_string();
        assert!(err.contains("future-dated"), "unexpected error: {err}");
    }

    #[test]
    fn future_dated_status_cannot_pin_a_thread() {
        let ks = owner_keystore();
        let owner = Keys::generate();
        // A read-only member still holds the #collab key, so they can sign and
        // seal a status rumor — that is precisely the threat in issue #16.
        let reader = Keys::generate();
        let now = crate::events::now_secs();

        let issue = build_issue(&owner, &ks, "still open", "body").unwrap();
        let root_id = issue.rumor_id.clone();
        let honest = build_status(&owner, &ks, &root_id, Status::Open, "open").unwrap();

        let e_tag = Tag::custom("e", vec![root_id.clone(), String::new(), String::new(), "root".to_string()]);
        let forged = seal_rumor_dated(
            &reader,
            &ks,
            KIND_STATUS_CLOSED,
            "closed",
            vec![e_tag],
            now + 10 * 365 * 86_400,
        );

        let wraps = vec![issue.wrap, honest.wrap, forged];
        let threads = fold_threads(read_all_at(&ks, &wraps, now));
        assert_eq!(threads.len(), 1);
        // Without the bound the forged status sorts last and wins forever.
        assert_eq!(threads[0].status_label(), "open");
    }
}
