//! Async client for the Aqua Timestamp Aggregator (`timestamp.inblock.io`).
//!
//! # When to reach for this crate
//!
//! The Aqua ecosystem has two timestamping service tiers, producing the
//! same artefact shape but with very different cost and latency profiles:
//!
//! - **SDK-direct timestamping.** Plug a `TimestampProvider` impl into
//!   [`aqua_rs_sdk`]'s `timestamp_aqua_tree_with_provider`. One hash, one
//!   transaction, seconds of latency. Best when you need the proof now.
//! - **The aggregator (this crate).** Submit a hash to a pooled service.
//!   The service holds it in an open epoch, builds a Merkle tree over the
//!   whole epoch's submissions, and anchors *the root* to EVM and qTSA in
//!   one transaction each. Every submitter gets a server-signed witness
//!   plus a Merkle inclusion proof plus the on-chain transaction plus the
//!   qTSA token, four anchors at the cost of one submission. Latency is
//!   up to one epoch (default 10 minutes).
//!
//! These are different service tiers, not interchangeable implementations.
//! This crate deliberately does **not** implement `TimestampProvider`:
//! that trait is synchronous in spirit and would smuggle a multi-minute
//! block into every SDK call site that uses it. Use this crate for any
//! workload where one-epoch latency is acceptable in exchange for cheap
//! bulk anchoring (session-close seals, identity claims at boot, signed
//! contracts in bulk).
//!
//! The closest CS prior art is Certificate Transparency log clients
//! (RFC 6962 / 9162). The server uses RFC 9162 for its Merkle tree and
//! the submit-then-poll-then-fetch shape is identical.
//!
//! # Quick start
//!
//! ```no_run
//! # use std::time::Duration;
//! # use aqua_timestamp_client::{AnchorMethod, TimestampClient};
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let client = TimestampClient::builder()
//!     .base_url("https://timestamp.inblock.io")
//!     .my_did("did:pkh:eip155:1:0x...")
//!     .signer(|message: &str| {
//!         // Sign `message` with your CAIP-122 key, return hex.
//!         Ok("0xdeadbeef".to_string())
//!     })
//!     .build()
//!     .await?;
//!
//! let leaf = [0xab; 32];
//! let receipt = client.submit(&leaf).await?;
//! let witness = client
//!     .await_witness(&receipt, AnchorMethod::Evm, Duration::from_secs(900))
//!     .await?;
//! // Splice witness.object_revision and witness.signature_revision into
//! // your own AquaTree using the SDK's existing primitives.
//! # Ok(())
//! # }
//! ```
//!
//! # Trust model
//!
//! On `build()`, the client fetches `/.well-known/aqua-identity` over
//! HTTPS, verifies the embedded `service_claim_server` Aqua-tree signs
//! correctly under its advertised DID, and pins that DID for the
//! lifetime of the client. Every subsequent witness signature must
//! recover to the pinned DID or the call fails with
//! [`ClientError::SignatureMismatch`].
//!
//! Across client instances, persistence is the caller's responsibility.
//! Read [`TimestampClient::server_identity`] after build to record the
//! discovered DID, then pass it back next time via
//! [`TimestampClientBuilder::expect_server_did`]. With
//! [`OnRotation::Refuse`] the build fails on any DID change; with
//! [`OnRotation::Warn`] it proceeds and exposes the rotation via
//! [`TimestampClient::rotation_detected`]; with [`OnRotation::Custom`] the
//! caller's callback decides.
//!
//! # Cargo features
//!
//! - `known-servers-file` (off by default) enables a small file-backed
//!   helper analogous to `~/.ssh/known_hosts`. See
//!   [`known_servers::KnownServersFile`].

mod auth;
mod client;
mod error;
mod hex_utils;
mod identity;
mod trust;
mod types;

#[cfg(feature = "known-servers-file")]
pub mod known_servers;

pub use client::{TimestampClient, TimestampClientBuilder};
pub use error::ClientError;
pub use trust::{OnRotation, RotationDecision, ServerRotation};
pub use types::{
    AnchorMethod, EpochSchedule, ServerIdentity, SubmissionReceipt, WitnessPair,
};
