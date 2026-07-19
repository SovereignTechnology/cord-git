//! `cord-git` — CLI for GRASP-P private repos (Phase 3: create/push/clone/
//! status/doctor). Invite/revoke/roster land in Phase 4.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use cord_core::{repo, Keystore};

#[derive(Parser)]
#[command(name = "cord-git", version, about = "Private git repos over GRASP-P")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new private repo: register it and link the current directory.
    Create {
        /// Human-friendly repo name (local only; never sent to the server).
        name: String,
        /// Node relay URL (ws:// or wss://).
        #[arg(long)]
        relay: String,
        /// Node blob server base URL (http:// or https://).
        #[arg(long)]
        server: String,
        /// Repo directory (defaults to the current directory).
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Pack, encrypt, upload, and publish the current state (client-side CAS).
    Push {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        /// Override the fork check.
        #[arg(long)]
        force: bool,
    },
    /// Clone a private repo you have a keystore for.
    Clone {
        /// Community id (the part after cord://).
        community_id: String,
        /// Destination directory.
        dir: PathBuf,
    },
    /// Rotate repo secrets (revocation primitive): deregister the old write key
    /// and re-key #state, then re-push. Locks out anyone holding old secrets.
    Rotate {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Show local keystore info for a community.
    Status { community_id: String },
    /// Connectivity + keystore self-check.
    Doctor { community_id: String },
    /// TEST-ONLY (requires CORD_GIT_ALLOW_DEBUG=1): publish a validly-signed
    /// 30641 with a future created_at — the reader-pinning attack vector.
    /// Used by e2e.sh to prove clients reject future-dated state roots.
    #[command(hide = true)]
    DebugForgeFutureState {
        community_id: String,
        /// Seconds into the future to date the event.
        #[arg(long)]
        ahead_secs: u64,
        /// Manifest blob hash (any 64-hex; need not exist).
        #[arg(long)]
        m: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Create {
            name,
            relay,
            server,
            dir,
        } => {
            let created = repo::create(&dir, &name, &relay, &server)?;
            println!("created {}", created.url);
            println!("  community_id: {}", created.community_id);
            println!("  alias:        {}", created.alias);
            println!("Run `cord-git push` here to publish your first commit.");
        }
        Cmd::Push { dir, force } => {
            let id = repo::push(&dir, force)?;
            println!("pushed. state root 30641 id: {id}");
        }
        Cmd::Clone { community_id, dir } => {
            repo::clone(&community_id, &dir)?;
            println!("cloned {} into {}", community_id, dir.display());
        }
        Cmd::Rotate { dir } => {
            let id = repo::rotate(&dir)?;
            println!("rotated. old secrets revoked. new state root 30641 id: {id}");
        }
        Cmd::Status { community_id } => {
            let ks = Keystore::load(&community_id).context("load keystore")?;
            println!("community: {}", ks.community_id);
            println!("name:      {}", ks.repo_name);
            println!("alias:     {}", ks.alias);
            println!("role:      {:?}", ks.role);
            println!("relays:    {:?}", ks.relays);
            println!("servers:   {:?}", ks.servers);
            println!("epoch:     {}", ks.epoch);
            println!("base 30641:{:?}", ks.manifest_prev);
        }
        Cmd::Doctor { community_id } => doctor(&community_id)?,
        Cmd::DebugForgeFutureState {
            community_id,
            ahead_secs,
            m,
        } => {
            anyhow::ensure!(
                std::env::var("CORD_GIT_ALLOW_DEBUG").as_deref() == Ok("1"),
                "debug commands require CORD_GIT_ALLOW_DEBUG=1"
            );
            let ks = Keystore::load(&community_id).context("load keystore")?;
            let tenant = ks.tenant_hex()?;
            let wk = ks.write_keys()?;
            let mut ev = cord_core::events::build_state_root(&wk, &tenant, &ks.alias, &m, 10, &[])?;
            // Re-sign with a future created_at.
            let tags = ev.tags.clone();
            let at = nostr::Timestamp::from_secs(nostr::Timestamp::now().as_secs() + ahead_secs);
            ev = nostr::prelude::FinalizeEvent::finalize(
                nostr::EventBuilder::new(nostr::Kind::Custom(30641), "").tags(tags).custom_created_at(at),
                &wk,
            )?;
            let relay = ks.relays.first().context("no relay")?;
            let out = cord_core::relay::publish(relay, &ev)?;
            println!("forged future-dated 30641: accepted={} msg={}", out.accepted, out.message);
        }
    }
    Ok(())
}

fn doctor(community_id: &str) -> Result<()> {
    let ks = Keystore::load(community_id).context("load keystore")?;
    println!("keystore: ok ({} role {:?})", ks.repo_name, ks.role);
    // Write-key derivation + PoP self-consistency.
    if ks.is_write() {
        let wk = ks.write_keys()?;
        let tenant = ks.tenant_hex()?;
        let sig = cord_core::crypto::key_pop_sig(&wk, &tenant, &ks.alias);
        let ok = cord_core::crypto::verify_key_pop(&wk.public_key().to_hex(), &sig, &tenant, &ks.alias);
        println!("write key + proof-of-possession: {}", if ok { "ok" } else { "FAILED" });
    }
    // Relay reachability + authenticated state-root selection.
    match cord_core::repo::latest_valid_state_root(&ks) {
        Ok(Some(state)) => {
            let id = state.id.to_hex();
            println!("relay + authenticated latest 30641: ok ({})", &id[..12]);
        }
        Ok(None) => println!("relay: ok (registered, no state root yet)"),
        Err(e) => println!("relay/auth check: FAILED ({e})"),
    }
    Ok(())
}
