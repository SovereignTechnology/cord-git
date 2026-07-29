//! cord-core — CORD-git-native client library for GRASP-P private repos.
//!
//! The server is content-blind; this crate holds all client secrets and
//! produces the server-visible wire shapes (30640/30641/3359/blobs). The
//! membership/crypto layer is CORD-git-native (Concord conformance deferred,
//! behind the same interfaces) — see `docs/grasp-p/phase3-design.md` §0.

pub mod blob;
pub mod collab;
pub mod crypto;
pub mod events;
pub mod git;
pub mod invite;
pub mod keystore;
pub mod manifest;
pub mod rekey;
pub mod relay;
pub mod repo;

pub use keystore::{BanEntry, Keystore, Role, RosterEntry};
pub use manifest::{Manifest, PackEntry};
