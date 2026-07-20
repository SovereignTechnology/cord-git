//! TEST-ONLY minimal nostr relay: store-and-replay in memory.
//!
//! Stands in for the invitee's own inbox relay in `scripts/e2e.sh` (the git
//! node normatively never carries invites, and its admission policy rejects
//! orphan gift wraps anyway). Supports EVENT (store + OK), REQ (replay
//! matching stored events + EOSE), CLOSE. No signature verification — clients
//! must verify everything they fetch, and the e2e exercises exactly that.
//!
//! Usage: `inbox-relay <port>` (binds 127.0.0.1).

use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

type Store = Arc<Mutex<Vec<Value>>>;

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .expect("usage: inbox-relay <port>");
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
    println!("inbox-relay listening on 127.0.0.1:{port}");
    let store: Store = Arc::new(Mutex::new(Vec::new()));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            let Ok(mut ws) = tungstenite::accept(stream) else {
                return;
            };
            loop {
                let msg = match ws.read() {
                    Ok(m) => m,
                    Err(_) => return,
                };
                match msg {
                    tungstenite::Message::Text(t) => {
                        let Ok(val) = serde_json::from_str::<Value>(t.as_str()) else {
                            continue;
                        };
                        let Some(arr) = val.as_array() else { continue };
                        match arr.first().and_then(Value::as_str) {
                            Some("EVENT") => {
                                let Some(ev) = arr.get(1) else { continue };
                                let id = ev
                                    .get("id")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string();
                                {
                                    let mut s = store.lock().unwrap();
                                    if !s.iter().any(|e| {
                                        e.get("id").and_then(Value::as_str) == Some(id.as_str())
                                    }) {
                                        s.push(ev.clone());
                                    }
                                }
                                let ok = json!(["OK", id, true, ""]).to_string();
                                let _ = ws.send(tungstenite::Message::Text(ok.into()));
                            }
                            Some("REQ") => {
                                let Some(sub) = arr.get(1).and_then(Value::as_str) else {
                                    continue;
                                };
                                let filters: Vec<&Value> = arr.iter().skip(2).collect();
                                let mut matched: Vec<Value> = {
                                    let s = store.lock().unwrap();
                                    s.iter()
                                        .filter(|ev| {
                                            filters.iter().any(|f| matches_filter(ev, f))
                                        })
                                        .cloned()
                                        .collect()
                                };
                                // Newest first, then apply the smallest limit.
                                matched.sort_by_key(|e| {
                                    std::cmp::Reverse(
                                        e.get("created_at").and_then(Value::as_u64).unwrap_or(0),
                                    )
                                });
                                if let Some(limit) = filters
                                    .iter()
                                    .filter_map(|f| f.get("limit").and_then(Value::as_u64))
                                    .max()
                                {
                                    matched.truncate(limit as usize);
                                }
                                for ev in matched {
                                    let m = json!(["EVENT", sub, ev]).to_string();
                                    let _ = ws.send(tungstenite::Message::Text(m.into()));
                                }
                                let eose = json!(["EOSE", sub]).to_string();
                                let _ = ws.send(tungstenite::Message::Text(eose.into()));
                            }
                            Some("CLOSE") => {}
                            _ => {}
                        }
                    }
                    tungstenite::Message::Ping(p) => {
                        let _ = ws.send(tungstenite::Message::Pong(p));
                    }
                    tungstenite::Message::Close(_) => return,
                    _ => {}
                }
            }
        });
    }
}

/// Minimal NIP-01 filter matching: ids, authors, kinds, #<single-letter>,
/// since, until. Prefix matching for ids/authors is not needed by the e2e.
fn matches_filter(ev: &Value, f: &Value) -> bool {
    let Some(obj) = f.as_object() else { return false };
    for (k, v) in obj {
        match k.as_str() {
            "ids" => {
                let id = ev.get("id").and_then(Value::as_str).unwrap_or("");
                if !contains_str(v, id) {
                    return false;
                }
            }
            "authors" => {
                let pk = ev.get("pubkey").and_then(Value::as_str).unwrap_or("");
                if !contains_str(v, pk) {
                    return false;
                }
            }
            "kinds" => {
                let kind = ev.get("kind").and_then(Value::as_u64).unwrap_or(u64::MAX);
                let ok = v
                    .as_array()
                    .map(|a| a.iter().any(|x| x.as_u64() == Some(kind)))
                    .unwrap_or(false);
                if !ok {
                    return false;
                }
            }
            "since" => {
                let at = ev.get("created_at").and_then(Value::as_u64).unwrap_or(0);
                if at < v.as_u64().unwrap_or(0) {
                    return false;
                }
            }
            "until" => {
                let at = ev.get("created_at").and_then(Value::as_u64).unwrap_or(0);
                if at > v.as_u64().unwrap_or(u64::MAX) {
                    return false;
                }
            }
            "limit" => {}
            tag if tag.starts_with('#') && tag.len() == 2 => {
                let name = &tag[1..];
                let tags = ev.get("tags").and_then(Value::as_array);
                let ok = tags
                    .map(|ts| {
                        ts.iter().any(|t| {
                            let Some(t) = t.as_array() else { return false };
                            t.first().and_then(Value::as_str) == Some(name)
                                && t.get(1)
                                    .and_then(Value::as_str)
                                    .map(|val| contains_str(v, val))
                                    .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);
                if !ok {
                    return false;
                }
            }
            _ => {} // unknown filter fields: ignore (permissive test relay)
        }
    }
    true
}

fn contains_str(list: &Value, needle: &str) -> bool {
    list.as_array()
        .map(|a| a.iter().any(|x| x.as_str() == Some(needle)))
        .unwrap_or(false)
}
