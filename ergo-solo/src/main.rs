//! ergo-solo — a modern Rust Stratum server for solo GPU mining to an Ergo node.
//!
//! Polls the node's `/mining/candidate`, serves Autolykos2 work to GPU miners over
//! EthereumStratum/1.0.0, validates submitted solutions, and POSTs found blocks to
//! `/mining/solution`. The block reward goes to the node's own reward address —
//! there is no custody and no payout configuration. A single self-contained Rust
//! binary.

mod config;
mod handler;
mod job_source;
mod node;
mod server;

use clap::Parser;

use config::{Cli, Config};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // RUST_LOG overrides; default to info so the common flow (jobs, blocks) is
    // visible without flags.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Config::from_cli(Cli::parse());
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        node = %config.node_url,
        bind = %config.bind_addr,
        vardiff_initial = config.vardiff.initial,
        vardiff_min = config.vardiff.min,
        vardiff_max = config.vardiff.max,
        partition = config.partition_nonce,
        "starting ergo-solo"
    );
    // Guard against re-hitting the starvation that motivated the whole-space default:
    // a 4-byte lane can't cover one mainnet share, so partitioning a single rig kills
    // its share rate. It's opt-in now, but warn loudly if someone turns it back on.
    if config.partition_nonce {
        tracing::warn!(
            "nonce partitioning is ON — each worker gets a 4-byte (2^32) lane. Use this \
             ONLY for a multi-rig farm: a single rig needs the whole 8-byte space, and on \
             mainnet a 4-byte lane is smaller than one share and will starve the miner. \
             Drop --partition unless several rigs share this server."
        );
    }
    server::run(config).await
}
