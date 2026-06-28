//! Per-connection stratum session: the deterministic state machine behind one
//! miner socket. Pure and clock-injected (the caller passes monotonic seconds),
//! so the whole accept/reject + vardiff + anti-cheat logic is unit-testable with
//! no network and no wall clock.
//!
//! Lifecycle: `Connected` -> [`Session::subscribe`] -> `Subscribed` ->
//! [`Session::authorize`] -> `Authorized`. The pool then pushes work via
//! [`Session::assign_job`] and the miner submits solutions via
//! [`Session::submit`], which enforces the connection's nonce lane
//! ([`crate::extranonce`]), classifies the share through the consensus PoW
//! ([`crate::share`]), enforces anti-cheat (stale job, duplicate nonce, below
//! target), retargets difficulty ([`crate::vardiff`]), and emits the PPLNS weight
//! ([`crate::job::share_weight`]) for the M2 accountant.

use std::collections::HashSet;

use num_bigint::BigUint;

use crate::extranonce::ExtraNonce;
use crate::job::{share_weight, Job};
use crate::share::{classify, ShareClass};
use crate::vardiff::VarDiff;

/// Handshake state of a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Socket open, no `mining.subscribe` yet.
    Connected,
    /// Subscribed; awaiting `mining.authorize`.
    Subscribed,
    /// Authorized; eligible to receive jobs and submit shares.
    Authorized,
}

/// Why a submitted share was not credited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// Submitted before completing subscribe + authorize.
    NotAuthorized,
    /// No job assigned, or the job id does not match the current job (the miner
    /// is working a template the pool has already replaced).
    StaleJob,
    /// The full nonce falls outside this connection's assigned extraNonce lane —
    /// the worker is grinding (or claiming) a nonce range that isn't its own.
    WrongLane,
    /// This `(job_id, nonce)` was already submitted — replay / double-credit attempt.
    DuplicateShare,
    /// The solution is valid PoW but above the worker's share target (too easy a
    /// claim for the assigned difficulty).
    BelowTarget,
}

/// Result of [`Session::submit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// `hit <= network_target`: a real block. Forward the solution to the node.
    /// Also counts as a share of `weight` for PPLNS.
    Block { weight: u128 },
    /// A valid pool share of `weight` for PPLNS.
    Accepted { weight: u128 },
    /// Rejected; nothing is credited.
    Rejected(RejectReason),
}

/// Running tallies for one session (for stats / monitoring).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionStats {
    pub accepted: u64,
    pub rejected: u64,
    pub blocks: u64,
    pub stale: u64,
    pub wrong_lane: u64,
    pub duplicate: u64,
    pub low_diff: u64,
}

/// One miner connection's authoritative state.
pub struct Session {
    state: SessionState,
    worker: Option<String>,
    /// The connection's assigned nonce lane (extraNonce partitioning + anti-cheat).
    extra_nonce: ExtraNonce,
    vardiff: VarDiff,
    current_job: Option<Job>,
    /// `(job_id, nonce)` already accepted/seen, to reject replays. Cleared when the
    /// job id changes (old nonces can never be valid against a new template).
    seen: HashSet<(u64, [u8; 8])>,
    /// Seconds (monotonic) of this worker's last accepted share, for vardiff.
    last_accept_secs: Option<f64>,
    stats: SessionStats,
}

impl Session {
    /// New session on nonce lane `extra_nonce` with the worker's starting vardiff.
    pub fn new(extra_nonce: ExtraNonce, vardiff: VarDiff) -> Self {
        Self {
            state: SessionState::Connected,
            worker: None,
            extra_nonce,
            vardiff,
            current_job: None,
            seen: HashSet::new(),
            last_accept_secs: None,
            stats: SessionStats::default(),
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn worker(&self) -> Option<&str> {
        self.worker.as_deref()
    }

    /// The connection's assigned nonce lane (for building the subscribe response /
    /// `set_extranonce`).
    pub fn extra_nonce(&self) -> &ExtraNonce {
        &self.extra_nonce
    }

    /// Current share-difficulty factor to advertise to the miner
    /// (`share_target = network_target * factor`).
    pub fn factor(&self) -> u64 {
        self.vardiff.factor()
    }

    /// The current per-worker share target = `network_target * factor`, i.e. the
    /// `boundary` to advertise in `mining.notify`. `None` until a job is assigned.
    pub fn share_target(&self) -> Option<BigUint> {
        self.current_job
            .as_ref()
            .map(|j| &j.target * BigUint::from(self.vardiff.factor().max(1)))
    }

    pub fn stats(&self) -> SessionStats {
        self.stats
    }

    pub fn current_job(&self) -> Option<&Job> {
        self.current_job.as_ref()
    }

    /// Handle `mining.subscribe`: `Connected`/`Subscribed` -> `Subscribed`.
    /// Idempotent; never downgrades an already-`Authorized` session.
    pub fn subscribe(&mut self) {
        if self.state == SessionState::Connected {
            self.state = SessionState::Subscribed;
        }
    }

    /// Handle `mining.authorize` for `worker`. Requires a prior subscribe.
    /// Returns whether authorization succeeded.
    pub fn authorize(&mut self, worker: &str) -> bool {
        if self.state == SessionState::Connected || worker.is_empty() {
            return false;
        }
        self.worker = Some(worker.to_string());
        self.state = SessionState::Authorized;
        true
    }

    /// Push a new job to the worker.
    ///
    /// The dedup set is keyed by `(job_id, nonce)`, so when the job **id** changes
    /// the old job's entries become permanently unreachable (any submit for the
    /// old id is rejected `StaleJob` before the dedup check) — we clear them to
    /// bound memory. A same-id refresh (same msg, re-sent) KEEPS the set, so a
    /// previously-accepted nonce can never be double-credited across the refresh.
    /// (`Job::clean` is the miner-facing "restart work" flag carried in
    /// `mining.notify`; it does not affect pool-side dedup.)
    pub fn assign_job(&mut self, job: Job) {
        let id_changed = self.current_job.as_ref().is_none_or(|c| c.id != job.id);
        if id_changed {
            self.seen.clear();
        }
        self.current_job = Some(job);
    }

    /// Handle `mining.submit`: classify a full `nonce` for `job_id` at monotonic
    /// time `now_secs`. Credits + retargets on accept; rejects
    /// stale/out-of-lane/duplicate/low.
    pub fn submit(&mut self, job_id: u64, nonce: [u8; 8], now_secs: f64) -> SubmitOutcome {
        if self.state != SessionState::Authorized {
            return self.reject(RejectReason::NotAuthorized);
        }
        // Must match the current job exactly — anything else is a stale template.
        let job = match &self.current_job {
            Some(j) if j.id == job_id => j.clone(),
            _ => return self.reject(RejectReason::StaleJob),
        };
        // The full nonce must lie in this connection's assigned lane.
        if !self.extra_nonce.contains(&nonce) {
            return self.reject(RejectReason::WrongLane);
        }
        // Replay / double-credit guard, before spending PoW on a known nonce.
        if self.seen.contains(&(job_id, nonce)) {
            return self.reject(RejectReason::DuplicateShare);
        }
        // The share is graded at the difficulty the miner currently holds (retarget
        // only affects the NEXT share). Run the consensus PoW, then transition.
        let factor = self.vardiff.factor();
        let class = classify(&job.submission(nonce), factor);
        self.credit(job_id, nonce, &job.target, factor, class, now_secs)
    }

    /// The post-classification state transition shared by production and tests:
    /// credit + remember + retarget on a valid share, reject below-target. Split
    /// out so the accept/block/weight/vardiff paths are deterministically testable
    /// without forging a real Autolykos2 solution. Assumes the lane + stale +
    /// duplicate guards in [`Session::submit`] already passed.
    fn credit(
        &mut self,
        job_id: u64,
        nonce: [u8; 8],
        target: &BigUint,
        factor: u64,
        class: ShareClass,
        now_secs: f64,
    ) -> SubmitOutcome {
        if class == ShareClass::BelowTarget {
            return self.reject(RejectReason::BelowTarget);
        }
        self.seen.insert((job_id, nonce));
        let weight = share_weight(target, factor);
        self.retarget(now_secs);
        self.stats.accepted += 1;
        if class == ShareClass::Block {
            self.stats.blocks += 1;
            SubmitOutcome::Block { weight }
        } else {
            SubmitOutcome::Accepted { weight }
        }
    }

    fn retarget(&mut self, now_secs: f64) {
        if let Some(prev) = self.last_accept_secs {
            self.vardiff.observe(now_secs - prev);
        }
        self.last_accept_secs = Some(now_secs);
    }

    fn reject(&mut self, reason: RejectReason) -> SubmitOutcome {
        self.stats.rejected += 1;
        match reason {
            RejectReason::StaleJob => self.stats.stale += 1,
            RejectReason::WrongLane => self.stats.wrong_lane += 1,
            RejectReason::DuplicateShare => self.stats.duplicate += 1,
            RejectReason::BelowTarget => self.stats.low_diff += 1,
            RejectReason::NotAuthorized => {}
        }
        SubmitOutcome::Rejected(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ergo_crypto::difficulty::get_target;

    // A hard target so an arbitrary nonce classifies BelowTarget under the real
    // consensus PoW — lets us exercise reject paths without a genuine solution.
    fn hard_target() -> BigUint {
        get_target(0x1b00_ffff)
    }

    fn easy_job(id: u64, clean: bool) -> Job {
        Job {
            id,
            msg: [0u8; 32],
            height: 1_786_189,
            version: 3,
            target: hard_target(),
            clean,
        }
    }

    fn vd() -> VarDiff {
        VarDiff::new(1000, 10.0, 1, 100_000)
    }

    // Tests drive the whole-space lane so any nonce is in-lane; the lane gate has
    // its own focused test below.
    fn authed() -> Session {
        let mut s = Session::new(ExtraNonce::whole(), vd());
        s.subscribe();
        assert!(s.authorize("miner.worker1"));
        s
    }

    // ----- handshake gating -----
    #[test]
    fn cannot_authorize_before_subscribe() {
        let mut s = Session::new(ExtraNonce::whole(), vd());
        assert!(!s.authorize("w"), "authorize before subscribe must fail");
        assert_eq!(s.state(), SessionState::Connected);
    }

    #[test]
    fn empty_worker_is_rejected() {
        let mut s = Session::new(ExtraNonce::whole(), vd());
        s.subscribe();
        assert!(!s.authorize(""));
        assert_eq!(s.state(), SessionState::Subscribed);
    }

    #[test]
    fn full_handshake_reaches_authorized() {
        let s = authed();
        assert_eq!(s.state(), SessionState::Authorized);
        assert_eq!(s.worker(), Some("miner.worker1"));
    }

    #[test]
    fn subscribe_does_not_downgrade_authorized() {
        let mut s = authed();
        s.subscribe();
        assert_eq!(s.state(), SessionState::Authorized);
    }

    // ----- submit gating / anti-cheat -----
    #[test]
    fn submit_before_authorize_is_rejected() {
        let mut s = Session::new(ExtraNonce::whole(), vd());
        s.subscribe();
        s.assign_job(easy_job(1, true));
        assert_eq!(
            s.submit(1, [0u8; 8], 0.0),
            SubmitOutcome::Rejected(RejectReason::NotAuthorized)
        );
    }

    #[test]
    fn submit_with_no_job_is_stale() {
        let mut s = authed();
        assert_eq!(
            s.submit(1, [0u8; 8], 0.0),
            SubmitOutcome::Rejected(RejectReason::StaleJob)
        );
    }

    #[test]
    fn submit_for_old_job_id_is_stale() {
        let mut s = authed();
        s.assign_job(easy_job(1, true));
        s.assign_job(easy_job(2, true)); // job 1 replaced
        assert_eq!(
            s.submit(1, [0u8; 8], 0.0),
            SubmitOutcome::Rejected(RejectReason::StaleJob)
        );
        assert_eq!(s.stats().stale, 1);
    }

    #[test]
    fn out_of_lane_nonce_is_rejected_before_pow() {
        // A 4-byte lane keyed by session id 0x11223344: a nonce with a different
        // prefix is another worker's slice and must be rejected WrongLane.
        let mut s = Session::new(ExtraNonce::from_session_id(0x1122_3344), vd());
        s.subscribe();
        assert!(s.authorize("miner.worker1"));
        s.assign_job(easy_job(1, true));
        let out = s.submit(1, [0x99, 0x99, 0x99, 0x99, 0, 0, 0, 1], 0.0);
        assert_eq!(out, SubmitOutcome::Rejected(RejectReason::WrongLane));
        assert_eq!(s.stats().wrong_lane, 1);
        // An in-lane nonce passes the lane gate (then fails on the hard target).
        let out = s.submit(1, [0x11, 0x22, 0x33, 0x44, 0, 0, 0, 1], 0.0);
        assert_eq!(out, SubmitOutcome::Rejected(RejectReason::BelowTarget));
    }

    #[test]
    fn below_target_solution_is_rejected_not_credited() {
        // factor 1000 against mainnet-hard target: an all-zero nonce is far above
        // the share target, so it classifies BelowTarget (real consensus PoW path).
        let mut s = authed();
        s.assign_job(easy_job(1, true));
        assert_eq!(
            s.submit(1, [0u8; 8], 0.0),
            SubmitOutcome::Rejected(RejectReason::BelowTarget)
        );
        assert_eq!(s.stats().accepted, 0);
        assert_eq!(s.stats().low_diff, 1);
    }

    #[test]
    fn below_target_share_is_not_remembered_so_it_regrades() {
        // A rejected (below-target) share must NOT enter the seen-set; resubmitting
        // the same nonce re-grades (BelowTarget), never silently Duplicate.
        let mut s = authed();
        s.assign_job(easy_job(1, true));
        assert_eq!(
            s.submit(1, [9u8; 8], 0.0),
            SubmitOutcome::Rejected(RejectReason::BelowTarget)
        );
        assert_eq!(
            s.submit(1, [9u8; 8], 1.0),
            SubmitOutcome::Rejected(RejectReason::BelowTarget)
        );
        assert_eq!(s.stats().duplicate, 0);
    }

    // ----- accept / block / weight / dedup via the `credit` seam -----
    // A real Autolykos2 solution can't be produced in a unit test, so we drive the
    // post-PoW transition directly with a synthetic ShareClass. This is the exact
    // code production runs after `classify`, so the coverage is faithful.

    #[test]
    fn credited_share_is_accepted_with_positive_weight_and_remembered() {
        let mut s = authed();
        s.assign_job(easy_job(1, true));
        let factor = s.factor();
        let out = s.credit(1, [3u8; 8], &hard_target(), factor, ShareClass::Share, 0.0);
        match out {
            SubmitOutcome::Accepted { weight } => assert!(weight >= 1),
            other => panic!("expected Accepted, got {other:?}"),
        }
        assert_eq!(s.stats().accepted, 1);
        // Now a real submit of the SAME (job_id, nonce) hits the dedup guard.
        assert_eq!(
            s.submit(1, [3u8; 8], 1.0),
            SubmitOutcome::Rejected(RejectReason::DuplicateShare)
        );
        assert_eq!(s.stats().duplicate, 1);
    }

    #[test]
    fn credited_block_counts_as_block_and_share() {
        let mut s = authed();
        s.assign_job(easy_job(1, true));
        let factor = s.factor();
        let out = s.credit(1, [4u8; 8], &hard_target(), factor, ShareClass::Block, 0.0);
        assert!(matches!(out, SubmitOutcome::Block { weight } if weight >= 1));
        assert_eq!(s.stats().blocks, 1);
        assert_eq!(s.stats().accepted, 1, "a block is also a counted share");
    }

    #[test]
    fn new_job_id_clears_seen_so_a_recycled_nonce_is_not_blocked() {
        let mut s = authed();
        s.assign_job(easy_job(1, true));
        s.credit(
            1,
            [5u8; 8],
            &hard_target(),
            s.factor(),
            ShareClass::Share,
            0.0,
        );
        s.assign_job(easy_job(2, true)); // id change -> seen cleared
        assert_eq!(s.current_job().map(|j| j.id), Some(2));
        // The nonce is now keyed under job 2 and the set was cleared, so it accepts.
        let out = s.credit(
            2,
            [5u8; 8],
            &hard_target(),
            s.factor(),
            ShareClass::Share,
            1.0,
        );
        assert!(matches!(out, SubmitOutcome::Accepted { .. }));
    }

    #[test]
    fn same_job_id_refresh_keeps_seen_to_block_double_credit() {
        let mut s = authed();
        s.assign_job(easy_job(7, true));
        s.credit(
            7,
            [6u8; 8],
            &hard_target(),
            s.factor(),
            ShareClass::Share,
            0.0,
        );
        // Re-send the SAME job id (a refresh) — dedup history must survive.
        s.assign_job(easy_job(7, false));
        // Resubmitting the already-accepted nonce is caught as a duplicate.
        assert_eq!(
            s.submit(7, [6u8; 8], 1.0),
            SubmitOutcome::Rejected(RejectReason::DuplicateShare)
        );
    }

    #[test]
    fn vardiff_retargets_after_accepts_change_the_factor() {
        let mut s = authed();
        s.assign_job(easy_job(1, true));
        let f0 = s.factor();
        // First accept sets the baseline time (no interval yet).
        s.credit(
            1,
            [10u8; 8],
            &hard_target(),
            s.factor(),
            ShareClass::Share,
            0.0,
        );
        // Second accept far too slow -> vardiff raises the factor (easier).
        s.credit(
            1,
            [11u8; 8],
            &hard_target(),
            s.factor(),
            ShareClass::Share,
            100.0,
        );
        assert!(s.factor() > f0, "slow shares should ease difficulty");
    }

    #[test]
    fn share_target_scales_network_target_by_factor() {
        let mut s = authed();
        s.assign_job(easy_job(1, true));
        let want = hard_target() * BigUint::from(s.factor());
        assert_eq!(s.share_target(), Some(want));
    }
}
