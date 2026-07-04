//! CLI / environment configuration for the solo stratum server.
//!
//! Everything has a sensible default so the common case is a one-liner:
//! `ergo-solo --node-url http://127.0.0.1:9052 --network testnet`. The vardiff
//! envelope is **network-aware** — the default share difficulty is mainnet-tuned
//! (~1 share / 15s across a wide range of hardware), but on testnet the network
//! difficulty is trivially low, so a fast GPU would flood a mainnet-tuned floor;
//! `--network testnet` pins a hard floor instead (learned the hard way running a
//! 3090 against a testnet node).

use std::time::Duration;

use clap::{Parser, ValueEnum};
use ergo_stratum::VarDiff;

/// Which Ergo network the target node is on. Only affects the default vardiff
/// envelope (the protocol and endpoints are identical on both).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Network {
    Mainnet,
    Testnet,
}

/// A modern Rust Stratum server for solo GPU mining to an Ergo node (Autolykos2).
///
/// It polls the node's `/mining/candidate`, serves work to GPU miners (Rigel,
/// lolMiner, …) over EthereumStratum/1.0.0, validates submitted Autolykos2
/// solutions, and POSTs found blocks to `/mining/solution`. The block reward goes
/// to the node's own configured reward address — zero custody, no payout config.
#[derive(Parser, Debug)]
#[command(name = "ergo-solo", version, about)]
pub struct Cli {
    /// Base URL of the Ergo node to mine to (must have mining enabled).
    #[arg(long, env = "ERGO_SOLO_NODE_URL", default_value = "http://127.0.0.1:9052")]
    pub node_url: String,

    /// host:port the stratum server listens on (point your GPU miner here).
    #[arg(long, env = "ERGO_SOLO_BIND", default_value = "0.0.0.0:3055")]
    pub bind: String,

    /// Node API key, if the node's API is key-protected (most local nodes aren't).
    #[arg(long, env = "ERGO_SOLO_API_KEY")]
    pub api_key: Option<String>,

    /// Network of the target node (only changes the default share difficulty).
    #[arg(long, env = "ERGO_SOLO_NETWORK", value_enum, default_value_t = Network::Mainnet)]
    pub network: Network,

    /// Seconds between `/mining/candidate` polls.
    #[arg(long, env = "ERGO_SOLO_POLL_SECS", default_value_t = 5)]
    pub poll_secs: u64,

    /// Block version stamped on jobs (>=2 selects the Autolykos2 N schedule).
    #[arg(long, env = "ERGO_SOLO_BLOCK_VERSION", default_value_t = 3)]
    pub block_version: u8,

    /// Enable per-connection nonce partitioning (a 4-byte extraNonce lane per
    /// worker). OFF by default — this is a *solo* server, so the common case is one
    /// or a few of your own rigs, and each needs the WHOLE 8-byte nonce space. A
    /// 4-byte lane is only 2^32 (~4.3e9) nonces; a single mainnet share is ~1e11
    /// nonces, so a lane STARVES the miner (it exhausts its slice in seconds, finds
    /// almost nothing, and floods stale rejects). Enable ONLY when running many rigs
    /// against this server that must not grind overlapping nonce ranges.
    #[arg(long, env = "ERGO_SOLO_PARTITION", default_value_t = false)]
    pub partition: bool,

    /// Initial vardiff factor (share_target = network_target × factor; bigger =
    /// easier). Overrides the network default.
    #[arg(long, env = "ERGO_SOLO_VARDIFF_INITIAL")]
    pub vardiff_initial: Option<u64>,

    /// Minimum (hardest) vardiff factor. Overrides the network default.
    #[arg(long, env = "ERGO_SOLO_VARDIFF_MIN")]
    pub vardiff_min: Option<u64>,

    /// Maximum (easiest) vardiff factor. Overrides the network default.
    #[arg(long, env = "ERGO_SOLO_VARDIFF_MAX")]
    pub vardiff_max: Option<u64>,

    /// Target seconds between shares per worker (vardiff aim point).
    #[arg(long, env = "ERGO_SOLO_VARDIFF_INTERVAL", default_value_t = 15.0)]
    pub vardiff_interval: f64,

    /// Inbound non-share message flood cap per second (0 = off, the solo default —
    /// share submissions are never counted, vardiff governs those).
    #[arg(long, env = "ERGO_SOLO_MAX_MSGS_PER_SEC", default_value_t = 0)]
    pub max_msgs_per_sec: u32,

    /// Max concurrent miner connections.
    #[arg(long, env = "ERGO_SOLO_MAX_CONNECTIONS", default_value_t = 1024)]
    pub max_connections: usize,

    /// Max connections per source IP (0 = off, the solo default).
    #[arg(long, env = "ERGO_SOLO_MAX_CONNS_PER_IP", default_value_t = 0)]
    pub max_conns_per_ip: u32,
}

/// The per-connection vardiff envelope (a fresh [`VarDiff`] controller per miner).
#[derive(Clone, Copy, Debug)]
pub struct VardiffCfg {
    pub initial: u64,
    pub min: u64,
    pub max: u64,
    pub interval_secs: f64,
}

impl VardiffCfg {
    /// Build a fresh per-connection vardiff controller.
    pub fn controller(&self) -> VarDiff {
        VarDiff::new(self.initial, self.interval_secs, self.min, self.max)
    }
}

/// Fully-resolved runtime configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub node_url: String,
    pub bind_addr: String,
    pub api_key: Option<String>,
    pub poll_interval: Duration,
    pub block_version: u8,
    pub partition_nonce: bool,
    pub vardiff: VardiffCfg,
    pub max_msgs_per_sec: u32,
    pub max_connections: usize,
    pub max_conns_per_ip: u32,
}

impl Config {
    /// Resolve CLI/env into a runtime config, applying the network-aware vardiff
    /// defaults for any factor the user did not override.
    pub fn from_cli(cli: Cli) -> Self {
        // Network defaults: mainnet aims for ~1 share/15s across a wide hardware
        // range; testnet pins a hard floor so a fast GPU can't flood the trivially
        // low testnet difficulty.
        let (def_initial, def_min, def_max) = match cli.network {
            Network::Mainnet => (1_000, 64, 10_000_000),
            Network::Testnet => (1, 1, 8),
        };
        let vardiff = VardiffCfg {
            initial: cli.vardiff_initial.unwrap_or(def_initial),
            min: cli.vardiff_min.unwrap_or(def_min),
            max: cli.vardiff_max.unwrap_or(def_max),
            interval_secs: cli.vardiff_interval,
        };
        Config {
            node_url: cli.node_url,
            bind_addr: cli.bind,
            api_key: cli.api_key,
            poll_interval: Duration::from_secs(cli.poll_secs.max(1)),
            block_version: cli.block_version,
            partition_nonce: cli.partition,
            vardiff,
            max_msgs_per_sec: cli.max_msgs_per_sec,
            max_connections: cli.max_connections,
            max_conns_per_ip: cli.max_conns_per_ip,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(args: &[&str]) -> Config {
        let mut argv = vec!["ergo-solo"];
        argv.extend_from_slice(args);
        Config::from_cli(Cli::parse_from(argv))
    }

    // Regression guard for the incident that motivated the default flip: a 4-byte
    // partition lane (2^32 nonces) is smaller than one mainnet share (~1e11), so a
    // single solo rig is starved. The resolved default MUST be whole-space.
    #[test]
    fn partitioning_is_off_by_default() {
        assert!(!cfg(&[]).partition_nonce, "solo default must be whole-space");
        assert!(!cfg(&["--network", "mainnet"]).partition_nonce);
    }

    #[test]
    fn partition_flag_opts_into_per_worker_lanes() {
        assert!(cfg(&["--partition"]).partition_nonce, "--partition enables lanes");
    }

    #[test]
    fn network_selects_the_default_vardiff_envelope() {
        let m = cfg(&["--network", "mainnet"]).vardiff;
        assert_eq!((m.initial, m.min, m.max), (1_000, 64, 10_000_000));
        let t = cfg(&["--network", "testnet"]).vardiff;
        assert_eq!((t.initial, t.min, t.max), (1, 1, 8));
    }

    #[test]
    fn explicit_vardiff_flags_override_the_network_default() {
        let v = cfg(&["--network", "mainnet", "--vardiff-initial", "42"]).vardiff;
        assert_eq!(v.initial, 42, "explicit --vardiff-initial wins over the default");
    }
}
