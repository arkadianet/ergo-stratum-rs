//! ergo-stratum — Autolykos2 share validation, Stratum protocol, and vardiff.
//!
//! Vendored from the kadia-pool stratum core; reuses the Ergo node's own ergo-crypto
//! consensus PoW (never sigma-rust).
//!
//! The pool's share layer: validate miner-submitted Autolykos2 solutions against
//! the network target (a real block) and the pool's easier share target (a pool
//! share), reusing the node's OWN consensus PoW (`ergo-crypto`) — never sigma-rust.
//! Plus a per-worker variable-difficulty (vardiff) controller.
//!
//! On top of those pure cores sit the job model, the JSON-RPC line protocol, and
//! the per-connection session state machine — also network-free and deterministic
//! (the session takes an injected monotonic clock), so the whole accept/reject +
//! anti-cheat + vardiff pipeline is unit-testable. A thin async TCP runtime that
//! reads lines, drives a `Session`, and writes frames is the only remaining piece
//! that touches the network.

pub mod extranonce;
pub mod job;
pub mod protocol;
pub mod session;
pub mod share;
pub mod vardiff;

pub use extranonce::ExtraNonce;
pub use job::{share_weight, Job};
pub use protocol::{parse_inbound, Inbound, Notification, ProtocolError, Request, Response};
pub use session::{RejectReason, Session, SessionState, SessionStats, SubmitOutcome};
pub use share::{classify, classify_hit, ShareClass, Submission};
pub use vardiff::VarDiff;
