//! Minimal blocking Nostr relay client (publish + REQ/EOSE fetch) over a raw
//! WebSocket. Sufficient for the CLI; no async runtime required.

use std::net::TcpStream;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use nostr::Event;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{connect, Message, WebSocket};

use crate::events::{KIND_NIP59_GIFT_WRAP, KIND_STREAM_WRAP};

type Ws = WebSocket<MaybeTlsStream<TcpStream>>;

fn set_read_timeout(ws: &mut Ws, dur: Duration) {
    match ws.get_mut() {
        MaybeTlsStream::Plain(s) => {
            let _ = s.set_read_timeout(Some(dur));
        }
        MaybeTlsStream::NativeTls(s) => {
            let _ = s.get_mut().set_read_timeout(Some(dur));
        }
        #[allow(unreachable_patterns)]
        _ => {}
    }
}

/// Result of publishing one event.
pub struct PublishOutcome {
    pub accepted: bool,
    pub message: String,
}

/// Publish `event`, returning the relay's OK verdict for it.
pub fn publish(relay_url: &str, event: &Event) -> Result<PublishOutcome> {
    let (mut ws, _resp) = connect(relay_url).map_err(|e| anyhow!("ws connect {relay_url}: {e}"))?;
    set_read_timeout(&mut ws, Duration::from_secs(10));
    let msg = serde_json::json!(["EVENT", event]).to_string();
    ws.send(Message::Text(msg.into()))
        .map_err(|e| anyhow!("ws send: {e}"))?;

    let deadline = Instant::now() + Duration::from_secs(15);
    let target = event.id.to_hex();
    while Instant::now() < deadline {
        match ws.read() {
            Ok(Message::Text(t)) => {
                let val: serde_json::Value = match serde_json::from_str(t.as_str()) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if val.get(0).and_then(|v| v.as_str()) == Some("OK") {
                    let id = val.get(1).and_then(|v| v.as_str()).unwrap_or("");
                    if id == target {
                        let accepted = val.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
                        let message = val
                            .get(3)
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let _ = ws.close(None);
                        return Ok(PublishOutcome { accepted, message });
                    }
                }
            }
            Ok(Message::Ping(p)) => {
                let _ = ws.send(Message::Pong(p));
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    Err(anyhow!("no OK received for event {target}"))
}

/// Hard cap on pagination pages per query — bounds the damage a malicious
/// relay (infinite junk) or a flooded address can do to one fetch. 128 pages
/// × 512 events = 65k events per author, far beyond any legitimate stream.
const MAX_PAGES: u32 = 128;

/// Fetch stored events matching `filter`, reading until EOSE. **Errors unless
/// EOSE actually arrives** — a timeout/`CLOSED`/dropped connection must never
/// be mistaken for a complete result set (an empty/stale set would look like
/// "repo never pushed" to a cloner).
pub fn fetch(relay_url: &str, filter: serde_json::Value) -> Result<Vec<Event>> {
    let (mut ws, _resp) = connect(relay_url).map_err(|e| anyhow!("ws connect {relay_url}: {e}"))?;
    set_read_timeout(&mut ws, Duration::from_secs(8));
    let sub = "cordq";
    let req = serde_json::json!(["REQ", sub, filter]).to_string();
    ws.send(Message::Text(req.into()))
        .map_err(|e| anyhow!("ws send: {e}"))?;

    let mut out = Vec::new();
    let mut got_eose = false;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        match ws.read() {
            Ok(Message::Text(t)) => {
                let val: serde_json::Value = match serde_json::from_str(t.as_str()) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                match val.get(0).and_then(|v| v.as_str()) {
                    Some("EVENT") if val.get(1).and_then(|v| v.as_str()) == Some(sub) => {
                        if let Some(ev) = val.get(2) {
                            if let Ok(event) = Event::from_json(ev.to_string()) {
                                out.push(event);
                            }
                        }
                    }
                    Some("EOSE") if val.get(1).and_then(|v| v.as_str()) == Some(sub) => {
                        got_eose = true;
                        break;
                    }
                    Some("CLOSED") if val.get(1).and_then(|v| v.as_str()) == Some(sub) => {
                        let reason = val
                            .get(2)
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let _ = ws.close(None);
                        return Err(anyhow!("subscription closed by relay: {reason}"));
                    }
                    Some("NOTICE") => {
                        let note = val
                            .get(1)
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        return Err(anyhow!("relay NOTICE: {note}"));
                    }
                    _ => {}
                }
            }
            Ok(Message::Ping(p)) => {
                let _ = ws.send(Message::Pong(p));
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(e) => {
                let _ = ws.close(None);
                return Err(anyhow!("ws read before EOSE: {e}"));
            }
        }
    }
    let _ = ws.send(Message::Text(serde_json::json!(["CLOSE", sub]).to_string().into()));
    let _ = ws.close(None);
    if !got_eose {
        return Err(anyhow!("no EOSE from relay within deadline"));
    }
    Ok(out)
}

/// All kind-30641 candidates for an alias (raw, unauthenticated — callers MUST
/// pass them through `repo::select_valid_state_root` before trusting).
pub fn state_root_candidates(relay_url: &str, alias: &str) -> Result<Vec<Event>> {
    let filter = serde_json::json!({ "kinds": [30641], "#d": [alias], "limit": 64 });
    fetch(relay_url, filter)
}

/// All kind-30640 candidates for an alias (raw, unauthenticated).
pub fn registration_candidates(relay_url: &str, alias: &str) -> Result<Vec<Event>> {
    let filter = serde_json::json!({ "kinds": [30640], "#d": [alias], "limit": 8 });
    fetch(relay_url, filter)
}

/// Genuine NIP-59 gift wraps ([`KIND_NIP59_GIFT_WRAP`]) addressed to
/// `recipient_hex` (raw, unauthenticated — callers MUST `verify()` each event
/// and treat contents as hostile until unwrapped successfully). Used against
/// the INVITEE'S INBOX RELAY, never a git node: this is the invite/promotion
/// plane, so it keeps the NIP-59 kind and did NOT move with the stream wraps
/// (see the two constants in `events.rs`).
/// Until-paginated: a flooded recipient address cannot push genuine wraps out
/// of the result window.
pub fn giftwraps_for(relay_url: &str, recipient_hex: &str) -> Result<Vec<Event>> {
    fetch_all(relay_url, giftwrap_filter(recipient_hex))
}

/// The REQ filter [`giftwraps_for`] issues. Split out so the invite plane's
/// kind can be asserted against what `invite::wrap_invite` actually emits.
pub fn giftwrap_filter(recipient_hex: &str) -> serde_json::Value {
    serde_json::json!({ "kinds": [KIND_NIP59_GIFT_WRAP], "#p": [recipient_hex] })
}

/// CORD stream wraps ([`KIND_STREAM_WRAP`]) authored by ANY of the given outer
/// keys (derived stream/rekey address keys). This is the READ side of every
/// wrap `build_*` emit site — it MUST name the same kind they do, or joins and
/// `#collab` threads come back EMPTY with no error at all (`roster`,
/// `issue/pr list`, `show`). Keep it on the named constant.
/// NIP-01 `authors` is an array: the
/// `#collab`/guestbook read paths pass the current derived stream pubkey
/// plus every retained prior one (GitLab #21 — pre-refounding wraps live
/// under prior stream keys and would otherwise never be fetched at all).
/// Raw, unauthenticated — callers MUST verify + parse.
/// Until-paginated (GitLab !13): rekey addresses are admitted during rotation
/// windows and ANY member can flood them with now-dated junk; genuine rekeys
/// are past-tweaked (up to 2 days back), so a fixed newest-first limit window
/// would let an attacker push the genuine wrap out of the result set. We
/// paginate backwards until the relay reports exhaustion; callers skip
/// unparseable wraps, so junk only costs bandwidth (bounded by the tenant's
/// storage quota on the server side).
pub fn wraps_by_authors(relay_url: &str, author_hexes: &[String]) -> Result<Vec<Event>> {
    fetch_all(relay_url, stream_wrap_filter(author_hexes))
}

/// The REQ filter [`wraps_by_authors`] issues. Split out so the emit sites can
/// assert, in unit tests, that they publish the kind this asks for: a
/// disagreement here is SILENT (empty reads, no error), so it is pinned rather
/// than reviewed. EVERY stream-wrap read must build its filter here — including
/// the ones that fetch through [`fetch_all_multi`] rather than
/// [`wraps_by_authors`] (`repo::ensure_no_existing_rekeys`, `repo::fold`) —
/// or it sits outside that pinning.
///
/// NO DUAL-KIND READ WINDOW (deliberate). This client reads ONLY
/// [`KIND_STREAM_WRAP`], and nothing rewrites or aliases the kind of
/// already-stored events, so stream wraps published at the pre-migration
/// [`KIND_NIP59_GIFT_WRAP`] are invisible here — silently, as empty results
/// (`repo::roster`, `repo::collab_threads`, `repo::fold`,
/// `repo::ensure_no_existing_rekeys`). The server's
/// `NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND` does NOT cover this: it gates ingest
/// and peer-sync only, never the REQs it serves to clients.
///
/// That was acceptable at migration time because the implementation had never
/// been used for real: no production repo predated the migration, so there was
/// no history to lose. (The only live private repo, `276a6003…` / alias
/// `1fcf1c68…`, was a throwaway deployment canary.) Confirmed by the operator
/// on 2026-07-28 — this is why the window was skipped, not an oversight.
///
/// If a read window is ever needed, widening this filter is NOT enough on its
/// own — it would fetch the legacy wraps and then throw them away at the three
/// parse-side kind checks (`collab::parse_collab_with_ring`,
/// `invite::parse_join_with_ring`, `rekey::parse_rekey`). Relax the filter and
/// all three TOGETHER, behind ONE shared predicate, so the accepted kind set
/// has a single definition.
pub fn stream_wrap_filter(author_hexes: &[String]) -> serde_json::Value {
    serde_json::json!({ "kinds": [KIND_STREAM_WRAP], "authors": author_hexes })
}

/// The single kind named by [`stream_wrap_filter`], for emit-site assertions.
#[cfg(test)]
pub(crate) fn stream_wrap_filter_kind() -> u64 {
    stream_wrap_filter(&[])["kinds"][0].as_u64().unwrap()
}

/// The single kind named by [`giftwrap_filter`], for emit-site assertions.
/// Mirror of [`stream_wrap_filter_kind`] — the invite plane gets the same
/// emit-kind == read-kind pinning as the stream plane.
#[cfg(test)]
pub(crate) fn giftwrap_filter_kind() -> u64 {
    giftwrap_filter("")["kinds"][0].as_u64().unwrap()
}

/// Fetch one event by id (pinpoint — cannot be flooded out of a limit
/// window). Used for post-publish read-back confirmations, where OK=true is
/// not a commit marker and a flooded author address must not be able to hide
/// the wrap we just published (GitLab !13).
pub fn event_by_id(relay_url: &str, id_hex: &str) -> Result<Vec<Event>> {
    let filter = serde_json::json!({ "ids": [id_hex], "limit": 1 });
    fetch(relay_url, filter)
}

/// Fetch ALL events matching `filter` from every relay in `relay_urls`,
/// unioned and deduped by id. A withholding relay must not be able to hide
/// rekeys/registrations from a member who has another node configured
/// (GitLab !12/!13): any single answering relay suffices. Errors only when
/// EVERY relay failed — one dead relay must never brick a fold (verify F3).
pub fn fetch_all_multi(
    relay_urls: &[String],
    filter: serde_json::Value,
) -> Result<Vec<Event>> {
    let mut out: Vec<Event> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut errors = Vec::new();
    let mut any_success = false;
    for url in relay_urls {
        match fetch_all(url, filter.clone()) {
            Ok(events) => {
                any_success = true;
                for ev in events {
                    if seen.insert(ev.id) {
                        out.push(ev);
                    }
                }
            }
            Err(e) => errors.push(format!("{url}: {e}")),
        }
    }
    if !any_success && !errors.is_empty() {
        return Err(anyhow!("every relay failed: {}", errors.join("; ")));
    }
    Ok(out)
}

/// Until-paginated fetch: drive `filter` (limit forced to 512/page) backwards
/// until the relay reports exhaustion, deduping by event id across pages.
/// Newest-first LIMIT semantics otherwise make any result set with more than
/// `limit` matching events silently incomplete — an attacker who can write to
/// the queried address exploits exactly that (GitLab !13).
///
/// Same-second floods (verify F1): NIP-01 `until` is INCLUSIVE, so when
/// ≥512 junk wraps share one crafted `created_at` second, stepping `until`
/// to the page's oldest timestamp never retreats past the junk. Progress is
/// therefore measured in NEW EVENT IDS, not timestamps: when a full page
/// yields zero new ids the whole same-second boundary is exhausted as far as
/// the relay can tell us, and `until` steps BELOW it. (Any genuine event
/// sharing that exact second behind ≥512 junk stays unreachable — NIP-01 has
/// no cursor — but for write/state-affecting rotations the fold-side
/// cross-check makes that loud; a hidden write-only demote epoch for a
/// read-only member is silent by design — their secrets are unchanged.)
fn fetch_all(relay_url: &str, filter: serde_json::Value) -> Result<Vec<Event>> {
    const PAGE: u64 = 512;
    let mut filter = filter;
    filter["limit"] = serde_json::json!(PAGE);
    let mut out: Vec<Event> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut until: Option<u64> = None;
    for _ in 0..MAX_PAGES {
        let mut page_filter = filter.clone();
        if let Some(u) = until {
            page_filter["until"] = serde_json::json!(u);
        }
        let page = fetch(relay_url, page_filter)?;
        let page_len = page.len();
        let mut new_in_page = 0usize;
        let mut oldest: Option<u64> = None;
        for ev in page {
            let at = ev.created_at.as_secs();
            oldest = Some(oldest.map_or(at, |o: u64| o.min(at)));
            if seen.insert(ev.id) {
                out.push(ev);
                new_in_page += 1;
            }
        }
        // An EMPTY page is the only reliable exhaustion signal: relays may
        // clamp `limit` (strfry defaults to 500 < our 512), so a short page
        // does NOT prove exhaustion (verify-round F4 — genuine wraps were
        // silently truncated on clamping inbox relays).
        if page_len == 0 {
            return Ok(out);
        }
        if new_in_page == 0 {
            // Non-empty page, zero new ids: either the relay is looping/
            // ignoring `until`, or everything at the `until` second has been
            // seen. Step below the boundary second; both cases then make
            // progress (or terminate at 0). A genuine loop is caught by
            // MAX_PAGES.
            let u = until.unwrap_or_else(|| oldest.unwrap_or(0));
            if u == 0 {
                return Ok(out);
            }
            until = Some(u - 1);
            continue;
        }
        // Progress: retreat to the oldest timestamp seen (never forward).
        if let Some(o) = oldest {
            until = Some(match until {
                Some(u) => u.min(o),
                None => o,
            });
        }
    }
    Err(anyhow!(
        "pagination did not converge within {MAX_PAGES} pages — relay is serving unbounded junk"
    ))
}
