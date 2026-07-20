//! `cord-git` — CLI for GRASP-P private repos: create/push/clone/rotate/
//! status/doctor (Phase 3) + invite/join/keygen/roster (Phase 4a).

use std::path::{Path, PathBuf};

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
    /// Revoke a member: banlist entry, refounding (root + channel + write-scope
    /// rekeys for retained members), 30640 rotation with normative widen ->
    /// wait-for-acceptance -> artifacts -> narrow sequencing, then re-push.
    Revoke {
        /// Identity to ban (npub1… or 64-hex x-only pubkey).
        npub: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Demote a writer to reader: standalone write-scope rotation + 30640
    /// w-set update — no refounding (they keep read access).
    Demote {
        /// Identity to demote (npub1… or 64-hex x-only pubkey).
        npub: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Promote a reader to writer: roster grant + write_secret delivered as a
    /// 3313-style whisper to THEIR inbox relay (never the git node — refused).
    Promote {
        /// Identity to promote (npub1… or 64-hex x-only pubkey).
        npub: String,
        /// The member's inbox relay URL (ws:// or wss://). NOT a git node.
        #[arg(long)]
        via: String,
        /// Also write the wrapped promotion to a file for offline handoff.
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Accept a promotion addressed to you: validate the delivered secret
    /// against the live registration and upgrade the local keystore.
    PromoteAccept {
        /// Your identity secret key (nsec1… or 64-hex).
        #[arg(long, env = "CORD_GIT_NSEC", hide_env_values = true)]
        nsec: String,
        /// Inbox relay to fetch the promotion from.
        #[arg(long, conflicts_with = "file")]
        relay: Option<String>,
        /// Offline handoff: read the promotion wrap from a file ("-" = stdin).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Fold pending rotations (revoke/demote rekeys) into your keystore:
    /// fetch the tenant-signed rekeys at the derived addresses epoch by epoch
    /// and apply your slots.
    Fold {
        community_id: String,
        /// Your identity secret key (nsec1… or 64-hex).
        #[arg(long, env = "CORD_GIT_NSEC", hide_env_values = true)]
        nsec: String,
    },
    /// Invite a member: grant a role and deliver the 3313 invite bundle to the
    /// INVITEE'S OWN inbox relay (never the git node — refused).
    Invite {
        /// Invitee identity (npub1… or 64-hex x-only pubkey).
        npub: String,
        /// Grant the push role (includes the write_secret in the bundle).
        #[arg(long)]
        write: bool,
        /// The invitee's inbox relay URL (ws:// or wss://). NOT a git node.
        #[arg(long)]
        via: String,
        /// Also write the wrapped invite to a file for offline handoff.
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Consume an invite: import the keystore and publish the guestbook Join
    /// (outer wrap signed by the derived guestbook key, never your npub).
    Join {
        /// Your identity secret key (nsec1… or 64-hex).
        #[arg(long, env = "CORD_GIT_NSEC", hide_env_values = true)]
        nsec: String,
        /// Inbox relay to fetch the invite from.
        #[arg(long, conflicts_with = "file")]
        relay: Option<String>,
        /// Offline handoff: read the invite wrap from a file ("-" = stdin).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Generate a fresh nostr identity (for join testing / new members).
    Keygen,
    /// File and read issues on the #collab channel (NIP-34 signed rumors).
    Issue {
        #[command(subcommand)]
        action: IssueCmd,
    },
    /// Submit and read patch series (PRs) on the #collab channel.
    Pr {
        #[command(subcommand)]
        action: PrCmd,
    },
    /// Show the roster: local grants + verified guestbook joins.
    Roster { community_id: String },
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
    /// TEST-ONLY (requires CORD_GIT_ALLOW_DEBUG=1): act as a read-only member
    /// abusing the derived guestbook (aux) key — attempt a blob PUT and a
    /// 30641 publish signed by it. Both MUST be rejected server-side.
    #[command(hide = true)]
    DebugReaderAttack { community_id: String },
    /// TEST-ONLY (requires CORD_GIT_ALLOW_DEBUG=1): act as a REMOVED member
    /// forging a state-scope rekey at the next-epoch address (they can derive
    /// the address key from the prior root, but cannot sign as the tenant).
    /// Remaining members' fold MUST reject it.
    #[command(hide = true)]
    DebugForgeRekey {
        community_id: String,
        /// The victim member pubkey to address a poisoned slot to.
        #[arg(long)]
        victim: String,
    },
    /// TEST-ONLY (requires CORD_GIT_ALLOW_DEBUG=1): the GitLab !13 attack —
    /// a read-only member floods the next-epoch rekey addresses with
    /// well-formed (validly signed by the derived address key) but
    /// unparseable junk wraps, trying to push genuine (past-tweaked) rekeys
    /// out of a newest-first limit window. With --same-second every junk
    /// wrap shares one crafted created_at second — the worst case for
    /// until-pagination (inclusive `until` semantics). Works only while the
    /// addresses are admitted (mid-rotation window); folds MUST paginate
    /// past the junk.
    #[command(hide = true)]
    DebugFloodRekey {
        community_id: String,
        /// Junk wraps to publish PER SCOPE address.
        #[arg(long, default_value = "600")]
        count: u32,
        /// Craft all junk with one identical created_at second.
        #[arg(long)]
        same_second: bool,
    },
    /// TEST-ONLY (requires CORD_GIT_ALLOW_DEBUG=1): stage a forked epoch —
    /// publish a GENUINE (tenant-signed) write-scope rekey at the next-epoch
    /// address carrying a poisoned write_secret for the victim, mimicking a
    /// second genuine rekey set from an aborted-rotation retry (GitLab !14).
    /// Any fold that sees it alongside the real one MUST fail loudly.
    #[command(hide = true)]
    DebugForkRekey {
        community_id: String,
        /// The member pubkey to poison (use the owner's hosting pubkey to
        /// fork the owner's own fold).
        #[arg(long)]
        victim: String,
    },
    /// TEST-ONLY (requires CORD_GIT_ALLOW_DEBUG=1): cross-alias squat
    /// (verify-round F-B) — register a FRESH alias whose aux set claims one
    /// next-epoch rekey address (derivable by any member), so the repo's
    /// widen hits "write key already registered". The rotation MUST still
    /// complete via the squat-tolerant minimal widen.
    #[command(hide = true)]
    DebugSquatRekey {
        community_id: String,
        /// Which scope's address to squat: state, collab, or write.
        #[arg(long)]
        scope: String,
    },
}

/// #collab is readable only back to the most recent rekey: the `#collab` stream
/// and seal keys are derived from the current channel key, which rolls on every
/// revoke/refounding. History before a rotation is intentionally unreadable —
/// a removed member holding the old key cannot read post-rotation threads, and
/// current members do not re-fetch pre-rotation ones with the new key.
#[derive(Subcommand)]
enum IssueCmd {
    /// File a new issue (signed by your identity; any member may post).
    New {
        /// Issue subject/title.
        subject: String,
        /// Issue body (markdown). Reads stdin if omitted.
        #[arg(long)]
        body: Option<String>,
        /// Your identity secret key (nsec1… or 64-hex).
        #[arg(long, env = "CORD_GIT_NSEC", hide_env_values = true)]
        nsec: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// List open/closed issue threads (readable back to the most recent rekey).
    List {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Show one issue thread with all comments, chronologically.
    Show {
        /// Issue root id (64-hex).
        root_id: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Comment on an issue (or PR) thread.
    Comment {
        /// Thread root id (64-hex).
        root_id: String,
        /// The specific message you are replying to (defaults to the root).
        #[arg(long)]
        reply: Option<String>,
        /// Comment body. Reads stdin if omitted.
        #[arg(long)]
        body: Option<String>,
        #[arg(long, env = "CORD_GIT_NSEC", hide_env_values = true)]
        nsec: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Close an issue (sets a 1632 status on the thread).
    Close {
        /// Issue root id (64-hex).
        root_id: String,
        /// Optional closing note.
        #[arg(long)]
        note: Option<String>,
        #[arg(long, env = "CORD_GIT_NSEC", hide_env_values = true)]
        nsec: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
}

/// See `IssueCmd` for the #collab readability boundary (most recent rekey).
#[derive(Subcommand)]
enum PrCmd {
    /// Submit a patch series from a git revision range (git format-patch).
    New {
        /// Revision range, e.g. `main..feature` or `HEAD~3..HEAD`.
        #[arg(long)]
        range: String,
        /// Series subject/title.
        #[arg(long)]
        subject: String,
        #[arg(long, env = "CORD_GIT_NSEC", hide_env_values = true)]
        nsec: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// List patch-series (PR) threads.
    List {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Show one PR thread: every patch + review comments, chronologically.
    Show {
        /// PR root id (64-hex).
        root_id: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Set a PR status: open|merged|closed|draft.
    Status {
        /// PR root id (64-hex).
        root_id: String,
        /// New state: open|merged|closed|draft.
        #[arg(long)]
        state: String,
        /// Optional note.
        #[arg(long)]
        note: Option<String>,
        #[arg(long, env = "CORD_GIT_NSEC", hide_env_values = true)]
        nsec: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
}

/// Resolve `--body` or read the whole of stdin when omitted.
fn body_or_stdin(body: Option<String>) -> Result<String> {
    match body {
        Some(b) => Ok(b),
        None => {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
            Ok(s)
        }
    }
}

/// Community id for a working dir (from its `.cord-git` pointer).
fn community_of(dir: &Path) -> Result<String> {
    let ptr = dir.join(".cord-git");
    let cid = std::fs::read_to_string(&ptr)
        .with_context(|| format!("no .cord-git pointer in {}", dir.display()))?
        .trim()
        .to_string();
    Ok(cid)
}

fn kind_label(kind: u16) -> &'static str {
    match kind {
        1621 => "issue",
        1617 => "patch",
        1111 => "comment",
        1630 => "status:open",
        1631 => "status:merged",
        1632 => "status:closed",
        1633 => "status:draft",
        _ => "msg",
    }
}

fn print_thread_summary(t: &cord_core::collab::Thread) {
    let title = t.root.subject.as_deref().unwrap_or("(no subject)");
    println!(
        "{}  [{}]  {}  ({} repl{}, by {})",
        &t.root.id[..12],
        t.status_label(),
        title,
        t.children.len(),
        if t.children.len() == 1 { "y" } else { "ies" },
        &t.root.author[..12],
    );
}

fn print_thread_full(t: &cord_core::collab::Thread) {
    let title = t.root.subject.as_deref().unwrap_or("(no subject)");
    println!("{} [{}]", title, t.status_label());
    println!("root {}  by {}  at {}", t.root.id, t.root.author, t.root.created_at);
    if !t.root.content.is_empty() {
        println!("\n{}\n", t.root.content);
    }
    for c in &t.children {
        println!(
            "  - [{}] {} by {} at {}",
            kind_label(c.kind),
            &c.id[..12],
            &c.author[..12],
            c.created_at
        );
        if !c.content.is_empty() {
            for line in c.content.lines() {
                println!("      {line}");
            }
        }
    }
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
        Cmd::Revoke { npub, dir } => {
            let id = repo::revoke(&dir, &npub)?;
            println!("revoked {npub}.");
            println!("refounding complete. new state root 30641 id: {id}");
            println!("retained members must run `cord-git fold` to pick up the new secrets.");
        }
        Cmd::Demote { npub, dir } => {
            let id = repo::demote(&dir, &npub)?;
            println!("demoted {npub} to reader.");
            println!("write scope rotated. new state root 30641 id: {id}");
            println!("remaining writers must run `cord-git fold` to pick up the new secret.");
        }
        Cmd::Promote {
            npub,
            via,
            out,
            dir,
        } => {
            let id = repo::promote(&dir, &npub, &via, out.as_deref())?;
            println!("promoted {npub} to writer. wrap id: {id}");
            println!("delivered via {via} (member inbox relay)");
            if let Some(p) = out {
                println!("offline copy: {}", p.display());
            }
        }
        Cmd::PromoteAccept { nsec, relay, file } => {
            let keys = nostr::Keys::parse(&nsec).context("invalid --nsec")?;
            let source = match (relay, file) {
                (Some(url), None) => repo::InviteSource::Relay(url),
                (None, Some(p)) if p.as_os_str() == "-" => repo::InviteSource::Stdin,
                (None, Some(p)) => repo::InviteSource::File(p),
                _ => anyhow::bail!("pass exactly one of --relay <inbox-url> or --file <wrap.json>"),
            };
            let cid = repo::promote_accept(&keys, source)?;
            println!("promotion accepted for community {cid} (push role active)");
        }
        Cmd::Fold { community_id, nsec } => {
            let keys = nostr::Keys::parse(&nsec).context("invalid --nsec")?;
            let applied = repo::fold(&community_id, &keys)?;
            if applied == 0 {
                println!("already up to date (no pending rotations)");
            } else {
                println!("folded {applied} rotation epoch(s) into the keystore");
            }
        }
        Cmd::Invite {
            npub,
            write,
            via,
            out,
            dir,
        } => {
            let id = repo::invite(&dir, &npub, write, &via, out.as_deref())?;
            let role = if write { "write" } else { "read" };
            println!("invited ({role}). wrap id: {id}");
            println!("delivered via {via} (invitee inbox relay)");
            if let Some(p) = out {
                println!("offline copy: {}", p.display());
            }
        }
        Cmd::Join { nsec, relay, file } => {
            let keys = nostr::Keys::parse(&nsec).context("invalid --nsec")?;
            let source = match (relay, file) {
                (Some(url), None) => repo::InviteSource::Relay(url),
                (None, Some(p)) if p.as_os_str() == "-" => repo::InviteSource::Stdin,
                (None, Some(p)) => repo::InviteSource::File(p),
                _ => anyhow::bail!("pass exactly one of --relay <inbox-url> or --file <wrap.json>"),
            };
            let cid = repo::join(&keys, source)?;
            println!("joined community {cid}");
            println!("run `cord-git clone {cid} <dir>` to get the repo");
        }
        Cmd::Keygen => {
            let keys = nostr::Keys::generate();
            println!("nsec: {}", keys.secret_key().to_secret_hex());
            println!("pubkey: {}", keys.public_key().to_hex());
        }
        Cmd::Roster { community_id } => {
            let view = repo::roster(&community_id)?;
            println!("grants ({}):", view.grants.len());
            for g in &view.grants {
                println!("  {} {:?} at {}", g.npub, g.role, g.granted_at);
            }
            println!("banned ({}):", view.banned.len());
            for b in &view.banned {
                println!("  banned {} at {}", b.npub, b.banned_at);
            }
            println!("guestbook joins ({}):", view.joins.len());
            for j in &view.joins {
                println!("  join {} at {}", j.member_pub, j.at);
            }
        }
        Cmd::Issue { action } => match action {
            IssueCmd::New {
                subject,
                body,
                nsec,
                dir,
            } => {
                let keys = nostr::Keys::parse(&nsec).context("invalid --nsec")?;
                let body = body_or_stdin(body)?;
                let id = repo::issue_new(&dir, &keys, &subject, &body)?;
                println!("filed issue {id}");
            }
            IssueCmd::List { dir } => {
                let cid = community_of(&dir)?;
                let threads = repo::collab_threads(&cid)?;
                let issues: Vec<_> = threads
                    .iter()
                    .filter(|t| t.root.kind == cord_core::collab::KIND_ISSUE)
                    .collect();
                println!("issues ({}):", issues.len());
                for t in issues {
                    print_thread_summary(t);
                }
            }
            IssueCmd::Show { root_id, dir } => {
                let cid = community_of(&dir)?;
                let threads = repo::collab_threads(&cid)?;
                match threads.iter().find(|t| t.root.id == root_id) {
                    Some(t) => print_thread_full(t),
                    None => anyhow::bail!("no readable thread {root_id} (wrong id, or before the last rekey)"),
                }
            }
            IssueCmd::Comment {
                root_id,
                reply,
                body,
                nsec,
                dir,
            } => {
                let keys = nostr::Keys::parse(&nsec).context("invalid --nsec")?;
                let body = body_or_stdin(body)?;
                let id = repo::issue_comment(&dir, &keys, &root_id, reply.as_deref(), &body)?;
                println!("commented {id}");
            }
            IssueCmd::Close {
                root_id,
                note,
                nsec,
                dir,
            } => {
                let keys = nostr::Keys::parse(&nsec).context("invalid --nsec")?;
                let id = repo::issue_close(&dir, &keys, &root_id, note.as_deref().unwrap_or(""))?;
                println!("closed {root_id} (status {id})");
            }
        },
        Cmd::Pr { action } => match action {
            PrCmd::New {
                range,
                subject,
                nsec,
                dir,
            } => {
                let keys = nostr::Keys::parse(&nsec).context("invalid --nsec")?;
                let root = repo::pr_new(&dir, &keys, &range, &subject)?;
                println!("submitted PR {root}");
            }
            PrCmd::List { dir } => {
                let cid = community_of(&dir)?;
                let threads = repo::collab_threads(&cid)?;
                let prs: Vec<_> = threads
                    .iter()
                    .filter(|t| t.root.kind == cord_core::collab::KIND_PATCH)
                    .collect();
                println!("pull requests ({}):", prs.len());
                for t in prs {
                    print_thread_summary(t);
                }
            }
            PrCmd::Show { root_id, dir } => {
                let cid = community_of(&dir)?;
                let threads = repo::collab_threads(&cid)?;
                match threads.iter().find(|t| t.root.id == root_id) {
                    Some(t) => print_thread_full(t),
                    None => anyhow::bail!("no readable PR {root_id} (wrong id, or before the last rekey)"),
                }
            }
            PrCmd::Status {
                root_id,
                state,
                note,
                nsec,
                dir,
            } => {
                let keys = nostr::Keys::parse(&nsec).context("invalid --nsec")?;
                let status = cord_core::collab::Status::parse(&state)?;
                let id = repo::pr_status(&dir, &keys, &root_id, status, note.as_deref().unwrap_or(""))?;
                println!("set PR {root_id} to {state} (status {id})");
            }
        },
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
        Cmd::DebugReaderAttack { community_id } => {
            anyhow::ensure!(
                std::env::var("CORD_GIT_ALLOW_DEBUG").as_deref() == Ok("1"),
                "debug commands require CORD_GIT_ALLOW_DEBUG=1"
            );
            let ks = Keystore::load(&community_id).context("load keystore")?;
            let tenant = ks.tenant_hex()?;
            let gb = ks.guestbook_keys()?;

            // 1: blob PUT authorized by the guestbook (aux) key — a read-only
            // member CAN derive this key, so the server must refuse it.
            let payload = b"reader-attack-blob".to_vec();
            let sha = cord_core::crypto::sha256_hex(&payload);
            let (_e, auth) = cord_core::events::build_blossom_auth(
                &gb,
                cord_core::events::BlobOp::Upload,
                &sha,
                &tenant,
                &ks.alias,
            )?;
            let server = ks.servers.first().context("no server")?;
            let put_rejected = cord_core::blob::put(server, &payload, &auth).is_err();
            println!("put_rejected={put_rejected}");

            // 2: a 30641 signed by the aux key — must be refused at admission.
            let ev = cord_core::events::build_state_root(
                &gb,
                &tenant,
                &ks.alias,
                &"0".repeat(64),
                10,
                &[],
            )?;
            let relay = ks.relays.first().context("no relay")?;
            let out = cord_core::relay::publish(relay, &ev)?;
            println!("state_rejected={} msg={}", !out.accepted, out.message);
        }
        Cmd::DebugForgeRekey {
            community_id,
            victim,
        } => {
            anyhow::ensure!(
                std::env::var("CORD_GIT_ALLOW_DEBUG").as_deref() == Ok("1"),
                "debug commands require CORD_GIT_ALLOW_DEBUG=1"
            );
            use cord_core::rekey::{self, Scope};
            let ks = Keystore::load(&community_id).context("load keystore")?;
            let root = ks.community_root_bytes()?;
            let next = ks.epoch + 1;
            let victim_pk = nostr::PublicKey::parse(&victim).context("invalid --victim")?;
            let relay = ks.relays.first().context("no relay")?;
            // Forge with a NON-tenant signer (the removed member does not
            // hold the hosting nsec) carrying poisoned secrets for the
            // victim. Remaining members' fold must never apply these.
            let forger = nostr::Keys::generate();
            let poison_state = nostr::serde_json::to_vec(&rekey::StateSlot {
                community_root: "42".repeat(32),
                state_key: "43".repeat(32),
                epoch: next,
                roster: vec![],
                banned: vec![],
            })?;
            let (state_wrap, _) = rekey::build_rekey(
                &forger,
                &community_id,
                &root,
                Scope::State,
                next,
                &[(victim_pk, poison_state)],
                None,
                &Scope::all(),
            )?;
            let out = cord_core::relay::publish(relay, &state_wrap)?;
            println!("forged_state_rekey_admitted={}", out.accepted);
            let poison_write = nostr::serde_json::to_vec(&rekey::WriteSlot {
                write_secret: "44".repeat(32),
                epoch: next,
            })?;
            let pc = match ks.write_secret_bytes()? {
                Some(s) => rekey::write_scope_prevcommit(&s, ks.epoch),
                None => rekey::write_scope_prevcommit(&[0u8; 32], ks.epoch),
            };
            let (write_wrap, _) = rekey::build_rekey(
                &forger,
                &community_id,
                &root,
                Scope::Write,
                next,
                &[(victim_pk, poison_write)],
                Some(&pc),
                &Scope::all(),
            )?;
            let out = cord_core::relay::publish(relay, &write_wrap)?;
            println!("forged_write_rekey_admitted={}", out.accepted);
        }
        Cmd::DebugFloodRekey {
            community_id,
            count,
            same_second,
        } => {
            anyhow::ensure!(
                std::env::var("CORD_GIT_ALLOW_DEBUG").as_deref() == Ok("1"),
                "debug commands require CORD_GIT_ALLOW_DEBUG=1"
            );
            use cord_core::rekey::{self, Scope};
            use nostr::prelude::FinalizeEvent;
            let ks = Keystore::load(&community_id).context("load keystore")?;
            let root = ks.community_root_bytes()?;
            let next = ks.epoch + 1;
            let relay = ks.relays.first().context("no relay")?;
            // Any root holder (read-only suffices) can derive the rekey
            // address keys — this is the !13 attacker. Junk wraps are validly
            // signed by the address key but carry undecryptable garbage, so
            // folds skip them; they are dated NOW (or all at ONE crafted
            // second — the worst case for inclusive-`until` pagination) to
            // push past-tweaked genuine rekeys out of a fixed newest-first
            // window.
            let crafted_at = nostr::Timestamp::now();
            for scope in [Scope::State, Scope::Collab, Scope::Write] {
                let addr = rekey::rekey_address(&root, &community_id, scope, next)?;
                let mut admitted = 0u32;
                for _ in 0..count {
                    // Unique per wrap (unique event ids), NOT valid base64 —
                    // parse_rekey rejects it at the content-decode step, which
                    // is precisely the unparseable-wrap skip path under test.
                    let builder = nostr::EventBuilder::new(
                        nostr::Kind::Custom(rekey::KIND_WRAP),
                        format!(
                            "junk-{}",
                            cord_core::crypto::sha256_hex(
                                &nostr::Keys::generate().public_key().to_bytes()
                            )
                        ),
                    );
                    let junk = if same_second {
                        builder.custom_created_at(crafted_at).finalize(&addr)?
                    } else {
                        builder.finalize(&addr)?
                    };
                    let out = cord_core::relay::publish(relay, &junk)?;
                    if out.accepted {
                        admitted += 1;
                    }
                }
                println!(
                    "flood {} addr {}: admitted={admitted}/{count}",
                    scope.name(),
                    &addr.public_key().to_hex()[..12]
                );
            }
        }
        Cmd::DebugForkRekey {
            community_id,
            victim,
        } => {
            anyhow::ensure!(
                std::env::var("CORD_GIT_ALLOW_DEBUG").as_deref() == Ok("1"),
                "debug commands require CORD_GIT_ALLOW_DEBUG=1"
            );
            use cord_core::rekey::{self, Scope};
            let ks = Keystore::load(&community_id).context("load keystore")?;
            let hosting = ks.hosting_keys().context("owner-only debug command")?;
            let root = ks.community_root_bytes()?;
            let next = ks.epoch + 1;
            let victim_pk = nostr::PublicKey::parse(&victim).context("invalid --victim")?;
            let relay = ks.relays.first().context("no relay")?;
            // A GENUINE-looking (tenant-signed) write-scope rekey with a
            // poisoned write_secret for the victim — the "second genuine set"
            // of the !14 abort-retry fork. The prevcommit is honest so the
            // only difference from a real rekey is the slot payload.
            let old_secret = ks
                .write_secret_bytes()?
                .context("keystore has no write secret")?;
            let pc = rekey::write_scope_prevcommit(&old_secret, ks.epoch);
            let poison = nostr::serde_json::to_vec(&rekey::WriteSlot {
                write_secret: cord_core::crypto::sha256_hex(b"forked-epoch-poison"),
                epoch: next,
            })?;
            let (wrap, _) = rekey::build_rekey(
                &hosting,
                &community_id,
                &root,
                Scope::Write,
                next,
                &[(victim_pk, poison)],
                Some(&pc),
                &[Scope::Write],
            )?;
            let out = cord_core::relay::publish(relay, &wrap)?;
            println!("forked_write_rekey_admitted={}", out.accepted);
        }
        Cmd::DebugSquatRekey { community_id, scope } => {
            anyhow::ensure!(
                std::env::var("CORD_GIT_ALLOW_DEBUG").as_deref() == Ok("1"),
                "debug commands require CORD_GIT_ALLOW_DEBUG=1"
            );
            use cord_core::rekey::{self, Scope};
            let scope = match scope.as_str() {
                "state" => Scope::State,
                "collab" => Scope::Collab,
                "write" => Scope::Write,
                other => anyhow::bail!("unknown scope {other:?} (state|collab|write)"),
            };
            let ks = Keystore::load(&community_id).context("load keystore")?;
            let root = ks.community_root_bytes()?;
            let next = ks.epoch + 1;
            let relay = ks.relays.first().context("no relay")?;
            // Any root holder (read-only suffices) derives the rekey address
            // key — this is the F-B squatter. Claim it as aux under a FRESH
            // alias so the repo's widen hits the key-conflict rejection.
            let addr = rekey::rekey_address(&root, &community_id, scope, next)?;
            let squatter = nostr::Keys::generate();
            let squat_alias = cord_core::crypto::sha256_hex(
                &nostr::Keys::generate().public_key().to_bytes(),
            )[..32]
                .to_string();
            let reg = cord_core::events::build_registration(
                &squatter,
                &nostr::Keys::generate(), // throwaway write key
                &[&addr],
                &squat_alias,
                &ks.relays,
                &ks.servers,
            )?;
            let out = cord_core::relay::publish(relay, &reg)?;
            println!(
                "squatted {} addr {} alias {}: accepted={}",
                scope.name(),
                &addr.public_key().to_hex()[..12],
                &squat_alias[..12],
                out.accepted
            );
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
