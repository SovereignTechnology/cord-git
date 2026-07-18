//! Minimal blocking Nostr relay client (publish + REQ/EOSE fetch) over a raw
//! WebSocket. Sufficient for the CLI; no async runtime required.

use std::net::TcpStream;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use nostr::Event;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{connect, Message, WebSocket};

type Ws = WebSocket<MaybeTlsStream<TcpStream>>;

fn set_read_timeout(ws: &mut Ws, dur: Duration) {
    // Phase 3 talks to localhost ws:// (plaintext). wss:// TLS peers get no
    // read timeout set here (harmless — the 15s deadline loop still bounds it).
    if let MaybeTlsStream::Plain(s) = ws.get_mut() {
        let _ = s.set_read_timeout(Some(dur));
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

/// Fetch stored events matching `filter` (a serde_json filter object), reading
/// until EOSE or timeout.
pub fn fetch(relay_url: &str, filter: serde_json::Value) -> Result<Vec<Event>> {
    let (mut ws, _resp) = connect(relay_url).map_err(|e| anyhow!("ws connect {relay_url}: {e}"))?;
    set_read_timeout(&mut ws, Duration::from_secs(8));
    let sub = "cordq";
    let req = serde_json::json!(["REQ", sub, filter]).to_string();
    ws.send(Message::Text(req.into()))
        .map_err(|e| anyhow!("ws send: {e}"))?;

    let mut out = Vec::new();
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
                        break;
                    }
                    _ => {}
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
    let _ = ws.send(Message::Text(serde_json::json!(["CLOSE", sub]).to_string().into()));
    let _ = ws.close(None);
    Ok(out)
}

/// Fetch the latest kind-30641 for an alias (highest created_at, tie → lowest id).
pub fn latest_state_root(relay_url: &str, alias: &str) -> Result<Option<Event>> {
    let filter = serde_json::json!({ "kinds": [30641], "#d": [alias], "limit": 32 });
    let mut events = fetch(relay_url, filter)?;
    events.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.to_hex().cmp(&b.id.to_hex()))
    });
    Ok(events.into_iter().next())
}
