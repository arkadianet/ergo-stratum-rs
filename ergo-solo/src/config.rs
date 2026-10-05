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
use ergo_stratum::extranonce::MAX_PREFIX_BYTES;
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
    #[arg(
        long,
        env = "ERGO_SOLO_NODE_URL",
        default_value = "http://127.0.0.1:9052"
    )]
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

    /// Seconds between `/mining/candidate` polls. With long-polling (the default)
    /// this is only the fallback cadence for nodes that don't support it, and the
    /// retry delay after an error.
    #[arg(long, env = "ERGO_SOLO_POLL_SECS", default_value_t = 5)]
    pub poll_secs: u64,

    /// Disable `/mining/candidate?longpoll=<msg>`. Long-polling makes the node
    /// answer the moment its template changes (instant new-block pickup); nodes
    /// without it answer immediately and ergo-solo falls back to `--poll-secs`.
    #[arg(long, env = "ERGO_SOLO_NO_LONGPOLL", default_value_t = false)]
    pub no_longpoll: bool,

    /// If no fresh candidate could be fetched for this many seconds (node down,
    /// restarting or resyncing), withdraw the stale job and disconnect miners so
    /// their backup pool can take over. 0 = keep serving the last job forever.
    #[arg(long, env = "ERGO_SOLO_STALE_WORK_SECS", default_value_t = 60)]
    pub stale_work_secs: u64,

    /// Block version stamped on jobs. Only Autolykos v2 (block version >= 2) is
    /// validated; this only selects the table-size schedule.
    #[arg(long, env = "ERGO_SOLO_BLOCK_VERSION", default_value_t = 3,
          value_parser = clap::value_parser!(u8).range(2..))]
    pub block_version: u8,

    /// Enable per-connection nonce partitioning: each connection gets its own
    /// `--partition-bytes` prefix lane so connections never grind overlapping
    /// nonces. OFF by default — whole-space is right for a few of your own rigs.
    #[arg(long, env = "ERGO_SOLO_PARTITION", default_value_t = false)]
    pub partition: bool,

    /// Pool-owned prefix bytes per lane when `--partition` is on. 2 (the
    /// default) leaves each connection 2^48 nonces (~4.7 min of work at 1 TH/s) and
    /// allows 65,536 concurrent connections. 4 leaves only 2^32 (~4 s at 1 GH/s)
    /// and starves real rigs.
    #[arg(long, env = "ERGO_SOLO_PARTITION_BYTES", default_value_t = 2,
          value_parser = clap::value_parser!(u8).range(1..=MAX_PREFIX_BYTES as i64))]
    pub partition_bytes: u8,

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

    /// Require this password in `mining.authorize` (the miner's `-p`/`--password`).
    /// Unset = any worker name is accepted. Set it before exposing the port to
    /// the internet (e.g. for rented hashrate).
    #[arg(long, env = "ERGO_SOLO_STRATUM_PASSWORD")]
    pub stratum_password: Option<String>,

    /// Don't send `mining.set_difficulty` before each job. By default it is sent
    /// (value 1 — the share target is in the job itself — or NiceHash units for
    /// NiceHash), as Miningcore does and as rental proxies (MiningRigRentals)
    /// require. Only disable it if a miner misbehaves on receiving it.
    #[arg(long, env = "ERGO_SOLO_NO_SET_DIFFICULTY", default_value_t = false)]
    pub no_set_difficulty: bool,

    /// Inbound non-share message flood cap per second (0 = off, the solo default —
    /// share submissions are never counted, vardiff governs those).
    #[arg(long, env = "ERGO_SOLO_MAX_MSGS_PER_SEC", default_value_t = 0)]
    pub max_msgs_per_sec: u32,

    /// Drop a connection that sends more than this many invalid submissions
    /// (malformed, below target, duplicate, out of lane) in a minute. Stale shares
    /// never count — they're just latency. 0 = off.
    #[arg(long, env = "ERGO_SOLO_MAX_INVALID_PER_MIN", default_value_t = 0)]
    pub max_invalid_per_min: u32,

    /// Max concurrent miner connections.
    #[arg(long, env = "ERGO_SOLO_MAX_CONNECTIONS", default_value_t = 1024)]
    pub max_connections: usize,

    /// Max connections per source IP (0 = off, the solo default).
    #[arg(long, env = "ERGO_SOLO_MAX_CONNS_PER_IP", default_value_t = 0)]
    pub max_conns_per_ip: u32,

    /// Seconds between per-worker stats lines in the log (hashrate, accepted,
    /// stale, rejected, blocks). 0 = off.
    #[arg(long, env = "ERGO_SOLO_STATS_INTERVAL_SECS", default_value_t = 300)]
    pub stats_interval_secs: u64,

    /// host:port for a read-only JSON stats endpoint (`curl http://HOST:PORT/`).
    /// Off unless set. Keep it on a private address.
    #[arg(long, env = "ERGO_SOLO_STATS_BIND")]
    pub stats_bind: Option<String>,
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
    pub longpoll: bool,
    /// Withdraw work after this long without a fresh candidate (`None` = never).
    pub stale_work: Option<Duration>,
    pub block_version: u8,
    /// Prefix bytes per connection lane, or `None` for the whole nonce space.
    pub partition_bytes: Option<usize>,
    pub vardiff: VardiffCfg,
    pub stratum_password: Option<String>,
    /// Send `mining.set_difficulty` before every `mining.notify`.
    pub set_difficulty: bool,
    pub max_msgs_per_sec: u32,
    pub max_invalid_per_min: u32,
    pub max_connections: usize,
    pub max_conns_per_ip: u32,
    pub stats_interval: Option<Duration>,
    pub stats_bind: Option<String>,
}

impl Config {
    /// Resolve CLI/env into a runtime config, applying the network-aware vardiff
    /// defaults for any factor the user did not override. Rejects inconsistent
    /// settings instead of silently normalizing them.
    pub fn from_cli(cli: Cli) -> Result<Self, String> {
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
        if vardiff.min == 0 || vardiff.min > vardiff.max {
            return Err(format!(
                "vardiff bounds must satisfy 1 <= min <= max (got min={}, max={})",
                vardiff.min, vardiff.max
            ));
        }
        if !(vardiff.min..=vardiff.max).contains(&vardiff.initial) {
            return Err(format!(
                "--vardiff-initial {} is outside [min={}, max={}]",
                vardiff.initial, vardiff.min, vardiff.max
            ));
        }
        if !(vardiff.interval_secs.is_finite() && vardiff.interval_secs > 0.0) {
            return Err(format!(
                "--vardiff-interval must be a positive number of seconds (got {})",
                vardiff.interval_secs
            ));
        }
        let secs = |s: u64| (s > 0).then(|| Duration::from_secs(s));
        Ok(Config {
            node_url: cli.node_url,
            bind_addr: cli.bind,
            api_key: cli.api_key,
            poll_interval: Duration::from_secs(cli.poll_secs.max(1)),
            longpoll: !cli.no_longpoll,
            stale_work: secs(cli.stale_work_secs),
            block_version: cli.block_version,
            partition_bytes: cli.partition.then_some(usize::from(cli.partition_bytes)),
            vardiff,
            stratum_password: cli.stratum_password.filter(|p| !p.is_empty()),
            set_difficulty: !cli.no_set_difficulty,
            max_msgs_per_sec: cli.max_msgs_per_sec,
            max_invalid_per_min: cli.max_invalid_per_min,
            max_connections: cli.max_connections,
            max_conns_per_ip: cli.max_conns_per_ip,
            stats_interval: secs(cli.stats_interval_secs),
            stats_bind: cli.stats_bind.filter(|s| !s.is_empty()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn try_cfg(args: &[&str]) -> Result<Config, String> {
        let mut argv = vec!["ergo-solo"];
        argv.extend_from_slice(args);
        Config::from_cli(Cli::try_parse_from(argv).map_err(|e| e.to_string())?)
    }

    fn cfg(args: &[&str]) -> Config {
        try_cfg(args).expect("valid config")
    }

    // Regression guard for the incident that motivated the default flip: a
    // partition lane starves a single solo rig, so the default MUST be whole-space.
    #[test]
    fn partitioning_is_off_by_default() {
        assert_eq!(
            cfg(&[]).partition_bytes,
            None,
            "solo default must be whole-space"
        );
        assert_eq!(cfg(&["--network", "mainnet"]).partition_bytes, None);
    }

    #[test]
    fn partition_flag_opts_into_two_byte_lanes_by_default() {
        assert_eq!(cfg(&["--partition"]).partition_bytes, Some(2));
        assert_eq!(
            cfg(&["--partition", "--partition-bytes", "3"]).partition_bytes,
            Some(3)
        );
        assert!(try_cfg(&["--partition", "--partition-bytes", "8"]).is_err());
        assert!(try_cfg(&["--partition", "--partition-bytes", "0"]).is_err());
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
        let v = cfg(&["--network", "mainnet", "--vardiff-initial", "4200"]).vardiff;
        assert_eq!(
            v.initial, 4200,
            "explicit --vardiff-initial wins over the default"
        );
    }

    #[test]
    fn inconsistent_vardiff_settings_are_rejected_not_normalized() {
        assert!(try_cfg(&["--vardiff-min", "100", "--vardiff-max", "10"]).is_err());
        assert!(
            try_cfg(&["--vardiff-initial", "1"]).is_err(),
            "below mainnet min 64"
        );
        assert!(try_cfg(&["--vardiff-interval", "0"]).is_err());
        assert!(try_cfg(&["--vardiff-interval", "NaN"]).is_err());
    }

    #[test]
    fn block_version_below_two_is_rejected() {
        assert!(try_cfg(&["--block-version", "1"]).is_err());
        assert_eq!(cfg(&["--block-version", "4"]).block_version, 4);
    }

    #[test]
    fn longpoll_and_stale_work_guard_are_on_by_default_and_can_be_disabled() {
        let c = cfg(&[]);
        assert!(c.longpoll);
        assert_eq!(c.stale_work, Some(Duration::from_secs(60)));
        let c = cfg(&["--no-longpoll", "--stale-work-secs", "0"]);
        assert!(!c.longpoll);
        assert_eq!(c.stale_work, None);
    }

    #[test]
    fn set_difficulty_is_on_by_default_and_can_be_disabled() {
        assert!(cfg(&[]).set_difficulty);
        assert!(!cfg(&["--no-set-difficulty"]).set_difficulty);
    }

    #[test]
    fn empty_password_means_no_password() {
        assert_eq!(cfg(&[]).stratum_password, None);
        assert_eq!(cfg(&["--stratum-password", ""]).stratum_password, None);
        assert_eq!(
            cfg(&["--stratum-password", "s3cret"])
                .stratum_password
                .as_deref(),
            Some("s3cret")
        );
    }
}
