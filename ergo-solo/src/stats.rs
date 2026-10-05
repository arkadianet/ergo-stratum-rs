//! Process-wide mining statistics: per-worker share accounting, block outcomes
//! and node health, shared by every connection and surfaced as periodic log lines
//! and an optional JSON endpoint.
//!
//! Workers are keyed by their authorized login, so totals survive reconnects
//! (not restarts). Hashrate is **estimated from accepted work**, not from what
//! the miner claims: each accepted share contributes its weight
//! ([`ergo_stratum::share_weight`] — the expected hashes to find a share at the
//! target it was assigned), so `Σ weight / elapsed` is the hashrate the server
//! actually received. That is the number to check rented hashrate against.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

use ergo_stratum::session::{RejectReason, SubmitOutcome};

/// Window for the "recent" hashrate estimate.
pub const RECENT_WINDOW: Duration = Duration::from_secs(600);

/// Most worker entries kept. Past it, a worker with no live connection is
/// forgotten — one that never had an accepted share first (junk logins can't
/// fake those without real hashing), else the least recently active — so
/// connect/authorize/disconnect churn under ever-new names can't grow memory
/// without bound or push out real workers' totals. (Workers with a live
/// connection are never evicted; those are bounded by `--max-connections`.)
pub const MAX_TRACKED_WORKERS: usize = 4096;

/// Shared statistics registry (wrap in an `Arc`).
#[derive(Debug)]
pub struct Stats {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    started: Instant,
    workers: BTreeMap<String, Worker>,
    max_workers: usize,
    blocks: BlockCounts,
    node: NodeHealth,
}

impl Inner {
    /// The entry for `name`, created (making room if needed) on first sight.
    fn worker_mut(&mut self, name: &str, now: Instant) -> &mut Worker {
        if !self.workers.contains_key(name) && self.workers.len() >= self.max_workers {
            self.evict_one_idle();
        }
        let w = self.workers.entry(name.to_string()).or_default();
        w.first_seen.get_or_insert(now);
        w
    }

    /// Forget one disconnected worker: workless ones first, then the least
    /// recently active. No-op if every tracked worker is connected.
    fn evict_one_idle(&mut self) {
        let victim = self
            .workers
            .iter()
            .filter(|(_, w)| w.connections == 0)
            .min_by_key(|(_, w)| (w.counts.accepted > 0, w.last_share.or(w.first_seen)))
            .map(|(name, _)| name.clone());
        if let Some(name) = victim {
            self.workers.remove(&name);
        }
    }
}

#[derive(Debug, Default)]
struct Worker {
    connections: u32,
    first_seen: Option<Instant>,
    last_share: Option<Instant>,
    counts: ShareCounts,
    /// Total accepted work (expected hashes).
    work: u128,
    /// Accepted work inside [`RECENT_WINDOW`], oldest first.
    recent: VecDeque<(Instant, u128)>,
}

/// Per-worker share tallies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ShareCounts {
    pub accepted: u64,
    pub blocks: u64,
    pub stale: u64,
    pub low_diff: u64,
    pub duplicate: u64,
    pub wrong_lane: u64,
    /// Malformed lines and unauthorized submits.
    pub invalid: u64,
}

/// Block outcomes as seen by the submitter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct BlockCounts {
    /// Winning nonces validated locally.
    pub found: u64,
    /// The node returned success for the submission.
    pub accepted: u64,
    /// The node refused it (or every retry failed).
    pub rejected: u64,
}

#[derive(Debug, Default)]
struct NodeHealth {
    height: Option<u32>,
    last_ok: Option<Instant>,
    jobs: u64,
    poll_errors: u64,
}

/// A point-in-time copy for logging / JSON.
#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub uptime_secs: u64,
    pub node: NodeSnapshot,
    pub blocks: BlockCounts,
    pub workers: Vec<WorkerSnapshot>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeSnapshot {
    pub height: Option<u32>,
    /// Seconds since the last successful `/mining/candidate`.
    pub last_candidate_age_secs: Option<u64>,
    pub jobs: u64,
    pub poll_errors: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct WorkerSnapshot {
    pub worker: String,
    pub connections: u32,
    #[serde(flatten)]
    pub counts: ShareCounts,
    /// Accepted work, in expected hashes.
    pub work_hashes: f64,
    /// Hashes/s over the last [`RECENT_WINDOW`] (or since first seen, if newer).
    pub hashrate_recent: f64,
    /// Hashes/s averaged since the worker was first seen — downtime included, so
    /// this is what was actually delivered over the whole period.
    pub hashrate_avg: f64,
    pub last_share_age_secs: Option<u64>,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new(Instant::now())
    }
}

impl Stats {
    pub fn new(now: Instant) -> Self {
        Self::with_max_workers(now, MAX_TRACKED_WORKERS)
    }

    fn with_max_workers(now: Instant, max_workers: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                started: now,
                workers: BTreeMap::new(),
                max_workers: max_workers.max(1),
                blocks: BlockCounts::default(),
                node: NodeHealth::default(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // Stats are best-effort; a panic elsewhere mustn't take them down.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A connection authorized as `worker`.
    pub fn worker_connected(&self, worker: &str, now: Instant) {
        self.lock().worker_mut(worker, now).connections += 1;
    }

    /// A connection authorized as `worker` closed.
    pub fn worker_disconnected(&self, worker: &str) {
        if let Some(w) = self.lock().workers.get_mut(worker) {
            w.connections = w.connections.saturating_sub(1);
        }
    }

    /// Record a graded submission.
    pub fn record_submit(&self, worker: &str, outcome: &SubmitOutcome, now: Instant) {
        let mut g = self.lock();
        let w = g.worker_mut(worker, now);
        match *outcome {
            SubmitOutcome::Accepted { weight, .. } | SubmitOutcome::Block { weight, .. } => {
                w.counts.accepted += 1;
                if matches!(outcome, SubmitOutcome::Block { .. }) {
                    w.counts.blocks += 1;
                }
                w.work = w.work.saturating_add(weight);
                w.last_share = Some(now);
                w.recent.push_back((now, weight));
                prune(&mut w.recent, now);
            }
            SubmitOutcome::Rejected(reason) => match reason {
                RejectReason::StaleJob => w.counts.stale += 1,
                RejectReason::BelowTarget => w.counts.low_diff += 1,
                RejectReason::DuplicateShare => w.counts.duplicate += 1,
                RejectReason::WrongLane => w.counts.wrong_lane += 1,
                RejectReason::NotAuthorized => w.counts.invalid += 1,
            },
        }
    }

    /// Record a malformed line from an authorized `worker`.
    pub fn record_invalid(&self, worker: &str, now: Instant) {
        self.lock().worker_mut(worker, now).counts.invalid += 1;
    }

    pub fn block_found(&self) {
        self.lock().blocks.found += 1;
    }

    pub fn block_accepted(&self) {
        self.lock().blocks.accepted += 1;
    }

    pub fn block_rejected(&self) {
        self.lock().blocks.rejected += 1;
    }

    /// A `/mining/candidate` succeeded at `height`; `new_job` if it was new work.
    pub fn candidate_ok(&self, height: u32, new_job: bool, now: Instant) {
        let mut g = self.lock();
        g.node.height = Some(height);
        g.node.last_ok = Some(now);
        if new_job {
            g.node.jobs += 1;
        }
    }

    pub fn candidate_err(&self) {
        self.lock().node.poll_errors += 1;
    }

    /// Copy everything out for reporting.
    pub fn snapshot(&self, now: Instant) -> Snapshot {
        let mut g = self.lock();
        let started = g.started;
        let age = |t: Option<Instant>| t.map(|t| now.saturating_duration_since(t).as_secs());
        let workers = g
            .workers
            .iter_mut()
            .map(|(name, w)| {
                prune(&mut w.recent, now);
                let first = w.first_seen.unwrap_or(started);
                let alive = now.saturating_duration_since(first).as_secs_f64();
                let recent_span = alive.min(RECENT_WINDOW.as_secs_f64());
                let recent_work: u128 = w.recent.iter().map(|(_, wt)| *wt).sum();
                WorkerSnapshot {
                    worker: name.clone(),
                    connections: w.connections,
                    counts: w.counts,
                    work_hashes: w.work as f64,
                    hashrate_recent: rate(recent_work, recent_span),
                    hashrate_avg: rate(w.work, alive),
                    last_share_age_secs: age(w.last_share),
                }
            })
            .collect();
        Snapshot {
            uptime_secs: now.saturating_duration_since(started).as_secs(),
            node: NodeSnapshot {
                height: g.node.height,
                last_candidate_age_secs: age(g.node.last_ok),
                jobs: g.node.jobs,
                poll_errors: g.node.poll_errors,
            },
            blocks: g.blocks,
            workers,
        }
    }
}

fn prune(recent: &mut VecDeque<(Instant, u128)>, now: Instant) {
    while let Some((t, _)) = recent.front() {
        if now.saturating_duration_since(*t) > RECENT_WINDOW {
            recent.pop_front();
        } else {
            break;
        }
    }
}

/// Hashes per second, or 0 over a too-short span (no meaningful estimate yet).
fn rate(work: u128, span_secs: f64) -> f64 {
    if span_secs < 1.0 {
        0.0
    } else {
        work as f64 / span_secs
    }
}

/// Human-readable hashrate: `245.31 MH/s`.
pub fn format_hashrate(hps: f64) -> String {
    const UNITS: [&str; 6] = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s"];
    let mut v = hps.max(0.0);
    let mut unit = 0;
    while v >= 1000.0 && unit < UNITS.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    format!("{v:.2} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(weight: u128) -> SubmitOutcome {
        SubmitOutcome::Accepted { weight, height: 1 }
    }

    #[test]
    fn hashrate_is_accepted_work_over_time() {
        let t0 = Instant::now();
        let s = Stats::new(t0);
        s.worker_connected("rig", t0);
        // 10 shares of 1e9 expected hashes each over 100s = 1e8 H/s.
        for i in 1..=10 {
            s.record_submit(
                "rig",
                &accepted(1_000_000_000),
                t0 + Duration::from_secs(i * 10),
            );
        }
        let snap = s.snapshot(t0 + Duration::from_secs(100));
        let w = &snap.workers[0];
        assert_eq!(w.counts.accepted, 10);
        assert!((w.hashrate_avg - 1e8).abs() < 1.0, "{}", w.hashrate_avg);
        assert!(
            (w.hashrate_recent - 1e8).abs() < 1.0,
            "{}",
            w.hashrate_recent
        );
        assert_eq!(w.last_share_age_secs, Some(0));
    }

    #[test]
    fn recent_window_forgets_old_work_but_average_keeps_it() {
        let t0 = Instant::now();
        let s = Stats::new(t0);
        s.worker_connected("rig", t0);
        s.record_submit("rig", &accepted(6_000_000_000), t0 + Duration::from_secs(1));
        // 20 minutes later, no new work: recent is 0, the average still counts it.
        let snap = s.snapshot(t0 + Duration::from_secs(1200));
        let w = &snap.workers[0];
        assert_eq!(w.hashrate_recent, 0.0);
        assert!((w.hashrate_avg - 5e6).abs() < 1.0, "{}", w.hashrate_avg);
    }

    #[test]
    fn rejects_are_tallied_by_reason_and_carry_no_work() {
        let t0 = Instant::now();
        let s = Stats::new(t0);
        for reason in [
            RejectReason::StaleJob,
            RejectReason::BelowTarget,
            RejectReason::DuplicateShare,
            RejectReason::WrongLane,
            RejectReason::NotAuthorized,
        ] {
            s.record_submit("rig", &SubmitOutcome::Rejected(reason), t0);
        }
        s.record_invalid("rig", t0);
        let w = &s.snapshot(t0).workers[0];
        assert_eq!(
            w.counts,
            ShareCounts {
                accepted: 0,
                blocks: 0,
                stale: 1,
                low_diff: 1,
                duplicate: 1,
                wrong_lane: 1,
                invalid: 2,
            }
        );
        assert_eq!(w.work_hashes, 0.0);
    }

    #[test]
    fn totals_survive_a_reconnect() {
        let t0 = Instant::now();
        let s = Stats::new(t0);
        s.worker_connected("rig", t0);
        s.record_submit("rig", &accepted(5), t0);
        s.worker_disconnected("rig");
        s.worker_connected("rig", t0 + Duration::from_secs(5));
        s.record_submit(
            "rig",
            &SubmitOutcome::Block {
                weight: 5,
                height: 9,
            },
            t0 + Duration::from_secs(6),
        );
        let w = &s.snapshot(t0 + Duration::from_secs(7)).workers[0];
        assert_eq!(w.connections, 1);
        assert_eq!((w.counts.accepted, w.counts.blocks), (2, 1));
        assert_eq!(w.work_hashes, 10.0);
    }

    #[test]
    fn worker_map_is_bounded_by_evicting_idle_disconnected_workers() {
        let t0 = Instant::now();
        let at = |s| t0 + Duration::from_secs(s);
        let s = Stats::with_max_workers(t0, 3);
        // A live worker and a disconnected one with recent work.
        s.worker_connected("live", at(0));
        s.worker_connected("paid", at(0));
        s.record_submit("paid", &accepted(7), at(50));
        s.worker_disconnected("paid");
        // Churn: connect/disconnect under ever-new names.
        for i in 0..100 {
            let name = format!("junk{i}");
            s.worker_connected(&name, at(100 + i)); // all newer than paid's share
            s.worker_disconnected(&name);
        }
        let snap = s.snapshot(at(300));
        let names: Vec<_> = snap.workers.iter().map(|w| w.worker.as_str()).collect();
        assert_eq!(snap.workers.len(), 3, "{names:?}");
        assert!(
            names.contains(&"live"),
            "a connected worker is never evicted"
        );
        assert!(
            names.contains(&"paid"),
            "real work outlives any amount of junk churn"
        );
    }

    #[test]
    fn a_full_map_of_connected_workers_still_admits_a_new_one() {
        // Live workers are bounded by the connection cap, not this map.
        let t0 = Instant::now();
        let s = Stats::with_max_workers(t0, 2);
        for name in ["a", "b", "c"] {
            s.worker_connected(name, t0);
        }
        assert_eq!(s.snapshot(t0).workers.len(), 3);
    }

    #[test]
    fn node_health_and_blocks_are_reported() {
        let t0 = Instant::now();
        let s = Stats::new(t0);
        s.candidate_ok(100, true, t0);
        s.candidate_ok(100, false, t0 + Duration::from_secs(1));
        s.candidate_err();
        s.block_found();
        s.block_accepted();
        let snap = s.snapshot(t0 + Duration::from_secs(4));
        assert_eq!(snap.node.height, Some(100));
        assert_eq!(snap.node.jobs, 1);
        assert_eq!(snap.node.poll_errors, 1);
        assert_eq!(snap.node.last_candidate_age_secs, Some(3));
        assert_eq!((snap.blocks.found, snap.blocks.accepted), (1, 1));
        // And it serializes for the JSON endpoint.
        let v = serde_json::to_value(&snap).unwrap();
        assert_eq!(v["node"]["height"], 100);
    }

    #[test]
    fn hashrate_formatting_picks_a_unit() {
        assert_eq!(format_hashrate(0.0), "0.00 H/s");
        assert_eq!(format_hashrate(245_310_000.0), "245.31 MH/s");
        assert_eq!(format_hashrate(1.5e12), "1.50 TH/s");
    }
}
