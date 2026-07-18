//! Blossom-subset blob client: authed PUT /upload, public GET /<sha256>.

use anyhow::{anyhow, Result};

fn base(server: &str) -> String {
    server.trim_end_matches('/').to_string()
}

/// PUT a blob's wire bytes to the server with a kind-24242 authorization header.
/// Returns Ok(()) on 200; errors carry the status + X-Reason.
pub fn put(server: &str, wire: &[u8], auth_header: &str) -> Result<()> {
    let url = format!("{}/upload", base(server));
    let client = reqwest::blocking::Client::new();
    let resp = client
        .put(&url)
        .header("Authorization", auth_header)
        .header("Content-Type", "application/octet-stream")
        .body(wire.to_vec())
        .send()
        .map_err(|e| anyhow!("blob PUT {url}: {e}"))?;
    if resp.status().is_success() {
        return Ok(());
    }
    let status = resp.status();
    let reason = resp
        .headers()
        .get("X-Reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    Err(anyhow!("blob PUT rejected: {status} {reason}"))
}

/// GET a blob by sha256 (public route). Returns the wire bytes.
pub fn get(server: &str, sha256_hex: &str) -> Result<Vec<u8>> {
    let url = format!("{}/{}", base(server), sha256_hex);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| anyhow!("blob GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("blob GET {url}: status {}", resp.status()));
    }
    Ok(resp.bytes().map_err(|e| anyhow!("blob body: {e}"))?.to_vec())
}

/// HEAD-style existence probe via GET (server has no cheap HEAD for our use).
pub fn exists(server: &str, sha256_hex: &str) -> bool {
    get(server, sha256_hex).is_ok()
}
