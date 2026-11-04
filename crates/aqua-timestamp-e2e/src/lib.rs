//! The aqua-timestamp e2e client as a library; `src/main.rs` is a thin command line over it.
//!
//! The crate compares SDK outputs and does the byte flips, the HTTP and the SIWE client signing.
//! Every hash, link, signature check, witness reading and verdict comes from aqua-rs-sdk.

pub mod flow;
pub mod identity;
pub mod selfcheck;
pub mod target;
pub mod witness;
