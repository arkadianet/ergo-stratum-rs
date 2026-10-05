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
mod stats;

use std::io::IsTerminal;

use clap::Parser;

use config::{Cli, Config};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // RUST_LOG overrides; default to info so the common flow (jobs, blocks) is
    // visible without flags. Colour only on a terminal — under systemd/journald
    // the escape codes would end up in the log verbatim.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    let config = match Config::from_cli(Cli::parse()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ergo-solo: invalid configuration: {e}");
            std::process::exit(2);
        }
    };
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        node = %config.node_url,
        bind = %config.bind_addr,
        longpoll = config.longpoll,
        stale_work_secs = config.stale_work.map_or(0, |d| d.as_secs()),
        vardiff_initial = config.vardiff.initial,
        vardiff_min = config.vardiff.min,
        vardiff_max = config.vardiff.max,
        vardiff_interval = config.vardiff.interval_secs,
        partition_bytes = config.partition_bytes.unwrap_or(0),
        password = config.stratum_password.is_some(),
        "starting ergo-solo"
    );
    if let Some(bytes) = config.partition_bytes {
        let lane_bits = 64 - 8 * bytes as u32;
        tracing::info!(
            prefix_bytes = bytes,
            "nonce partitioning ON — each connection searches its own 2^{lane_bits} nonce lane"
        );
        if lane_bits < 48 {
            tracing::warn!(
                "a 2^{lane_bits} lane is small: a fast rig (or a rental proxy) can exhaust it \
                 within one job and starve. Prefer --partition-bytes 2."
            );
        }
    }
    server::run(config).await
}
