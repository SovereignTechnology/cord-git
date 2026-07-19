//! Blossom-subset blob client: authed PUT /upload, public GET /<sha256>.

use std::io::Read;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};

/// Client-side blob cap (mirrors the server default max_blob_bytes = 256 MiB).
const MAX_BLOB_BYTES: u64 = 256 * 1024 * 1024;

fn base(server: &str) -> String {
    server.trim_end_matches('/').to_string()
}

fn client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .build()?)
}

/// PUT a blob's wire bytes to the server with a kind-24242 authorization header.
/// Returns Ok(()) on 200; errors carry the status + X-Reason.
pub fn put(server: &str, wire: &[u8], auth_header: &str) -> Result<()> {
    let url = format!("{}/upload", base(server));
    let resp = client()?
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

/// GET a blob by sha256 (public route). Returns the wire bytes. Reads at most
/// MAX_BLOB_BYTES+1 and fails rather than OOM-ing on a hostile unbounded body.
pub fn get(server: &str, sha256_hex: &str) -> Result<Vec<u8>> {
    let url = format!("{}/{}", base(server), sha256_hex);
    let resp = client()?
        .get(&url)
        .send()
        .map_err(|e| anyhow!("blob GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("blob GET {url}: status {}", resp.status()));
    }
    let mut limited = resp.take(MAX_BLOB_BYTES + 1);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .map_err(|e| anyhow!("blob body read: {e}"))?;
    if buf.len() as u64 > MAX_BLOB_BYTES {
        bail!("blob exceeds the {MAX_BLOB_BYTES}-byte cap");
    }
    Ok(buf)
}

/// HEAD-style existence probe via GET (server has no cheap HEAD for our use).
pub fn exists(server: &str, sha256_hex: &str) -> bool {
    get(server, sha256_hex).is_ok()
}
