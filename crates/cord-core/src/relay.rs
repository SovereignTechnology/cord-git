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
