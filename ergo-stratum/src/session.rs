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
//! target), feeds vardiff ([`crate::vardiff`]), and emits the share's work
//! ([`crate::job::share_weight`]).
//!
//! **Assignments.** Every `mining.notify` the miner receives is an
//! [`Assignment`]: a job *plus the share factor it was advertised at*, under a
//! connection-local id. A submission is graded against the assignment it names —
//! never against whatever the vardiff controller says *now* — so retargeting can't
//! retroactively reject shares mined at the boundary the miner was actually given.
//! A difficulty change is delivered as a fresh assignment
//! ([`Session::take_retarget`]) with `clean = false`.
//!
//! **Recent jobs.** The node publishes several templates per height (an early
//! empty one, then refreshes as the mempool changes) and accepts solutions for
//! recent ones, so any of the last [`RECENT_ASSIGNMENTS`] assignments at the
//! *current height* stays gradeable. Work for an older height is truly stale.

use std::collections::{HashSet, VecDeque};

use num_bigint::BigUint;

use crate::extranonce::ExtraNonce;
use crate::job::{share_weight, Job};
use crate::share::{classify, ShareClass};
use crate::vardiff::VarDiff;

/// How many recent assignments stay gradeable (only those at the current height
/// actually are). Matches the depth of the node's own retained-template ring.
pub const RECENT_ASSIGNMENTS: usize = 16;

/// Longest miner user-agent kept (it is logged and matched, never trusted).
pub const MAX_AGENT_LEN: usize = 64;

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
    /// Unknown assignment id, or one for an older block height (the miner is
    /// working a template the network has moved past).
    StaleJob,
    /// The full nonce falls outside this connection's assigned extraNonce lane —
    /// the worker is grinding (or claiming) a nonce range that isn't its own.
    WrongLane,
    /// This `(template, nonce)` was already accepted — replay / double-credit.
    DuplicateShare,
    /// The solution does not meet the share target it was assigned.
    BelowTarget,
}

/// Result of [`Session::submit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// `hit < network_target`: a real block at `height`. Forward the nonce to the
    /// node. Also counts as a share of `weight`.
    Block { weight: u128, height: u32 },
    /// A valid share of `weight` (expected hashes) at `height`.
    Accepted { weight: u128, height: u32 },
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

/// One `mining.notify` as the miner received it: the job, the share factor it was
/// advertised at, and the connection-local id the miner will echo back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    /// Connection-local wire job id (what `mining.submit` names).
    pub id: u64,
    pub job: Job,
    /// Share factor advertised with this assignment (`boundary = target * factor`).
    pub factor: u64,
    /// Whether the miner must abandon prior work (the height changed).
    pub clean: bool,
}

impl Assignment {
    /// The share boundary advertised in `mining.notify`.
    pub fn boundary(&self) -> BigUint {
        &self.job.target * BigUint::from(self.factor.max(1))
    }
}

/// One miner connection's authoritative state.
pub struct Session {
    state: SessionState,
    worker: Option<String>,
    /// The miner software's self-description from `mining.subscribe`.
    agent: Option<String>,
    /// The connection's assigned nonce lane (extraNonce partitioning + anti-cheat).
    extra_nonce: ExtraNonce,
    vardiff: VarDiff,
    /// The newest job from the node (defines the current height).
    latest_job: Option<Job>,
    /// Recently issued assignments, oldest first.
    assignments: VecDeque<Assignment>,
    next_assignment_id: u64,
    /// `(msg, nonce)` already accepted at the current height, to reject replays.
    /// Keyed by the template `msg` (not an id), so re-advertising a template at a
    /// new difficulty can't re-open a nonce. Cleared when the height changes.
    seen: HashSet<([u8; 32], [u8; 8])>,
    /// Vardiff moved: the miner needs a fresh assignment at the new factor.
    retarget_pending: bool,
    stats: SessionStats,
}

impl Session {
    /// New session on nonce lane `extra_nonce` with the worker's starting vardiff.
    pub fn new(extra_nonce: ExtraNonce, vardiff: VarDiff) -> Self {
        Self {
            state: SessionState::Connected,
            worker: None,
            agent: None,
            extra_nonce,
            vardiff,
            latest_job: None,
            assignments: VecDeque::new(),
            next_assignment_id: 1,
            seen: HashSet::new(),
            retarget_pending: false,
            stats: SessionStats::default(),
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn worker(&self) -> Option<&str> {
        self.worker.as_deref()
    }

    /// Record the user-agent a miner announced in `mining.subscribe`, reduced to
    /// printable ASCII and capped at [`MAX_AGENT_LEN`] (it ends up in logs).
    pub fn set_agent(&mut self, agent: &str) {
        let clean: String = agent
            .chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .take(MAX_AGENT_LEN)
            .collect();
        self.agent = (!clean.is_empty()).then_some(clean);
    }

    /// The miner's announced user-agent, if any.
    pub fn agent(&self) -> Option<&str> {
        self.agent.as_deref()
    }

    /// NiceHash's proxy reads `mining.set_difficulty` in its own units (it
    /// identifies itself in the subscribe user-agent).
    pub fn is_nicehash(&self) -> bool {
        self.agent
            .as_deref()
            .is_some_and(|a| a.to_ascii_lowercase().contains("nicehash"))
    }

    /// The connection's assigned nonce lane (for building the subscribe response /
    /// `set_extranonce`).
    pub fn extra_nonce(&self) -> &ExtraNonce {
        &self.extra_nonce
    }

    /// The vardiff controller's current share factor — what the *next* assignment
    /// will advertise (`share_target = network_target * factor`).
    pub fn factor(&self) -> u64 {
        self.vardiff.factor()
    }

    /// The share target the next assignment would advertise (current job's
    /// target × current factor). `None` until a job is known.
    pub fn share_target(&self) -> Option<BigUint> {
        self.latest_job
            .as_ref()
            .map(|j| &j.target * BigUint::from(self.vardiff.factor().max(1)))
    }

    pub fn stats(&self) -> SessionStats {
        self.stats
    }

    /// The newest job from the node.
    pub fn current_job(&self) -> Option<&Job> {
        self.latest_job.as_ref()
    }

    /// The assignment with wire id `id`, if still retained.
    pub fn assignment(&self, id: u64) -> Option<&Assignment> {
        self.assignments.iter().find(|a| a.id == id)
    }

    /// Handle `mining.subscribe`: `Connected`/`Subscribed` -> `Subscribed`.
    /// Idempotent; never downgrades an already-`Authorized` session.
    pub fn subscribe(&mut self) {
        if self.state == SessionState::Connected {
            self.state = SessionState::Subscribed;
        }
    }

    /// Handle `mining.authorize` for `worker`. Requires a prior subscribe.
    /// Returns whether authorization succeeded. (Credential checks are the
    /// caller's policy; this only enforces the handshake order.)
    ///
    /// A connection's identity is fixed once authorized: re-authorizing under
    /// the same name is accepted (idempotent), under a different name refused —
    /// otherwise one socket could mint unlimited worker identities.
    pub fn authorize(&mut self, worker: &str) -> bool {
        if self.state == SessionState::Connected || worker.is_empty() {
            return false;
        }
        if self.worker.as_deref().is_some_and(|w| w != worker) {
            return false;
        }
        self.worker = Some(worker.to_string());
        self.state = SessionState::Authorized;
        true
    }

    /// Record a new job from the node and, if authorized, issue it to the miner.
    /// Returns the assignment to advertise in `mining.notify` (`None` while the
    /// handshake is incomplete — the job is still remembered and issued on
    /// [`Session::issue`] after authorization).
    pub fn assign_job(&mut self, job: Job, now_secs: f64) -> Option<Assignment> {
        let height_changed = self
            .latest_job
            .as_ref()
            .is_none_or(|j| j.height != job.height);
        if height_changed {
            // Nonces for an older height can never be credited again (they are
            // rejected StaleJob first), so drop them to bound memory.
            self.seen.clear();
        }
        self.latest_job = Some(job);
        self.issue(now_secs)
    }

    /// Issue the latest job at the current vardiff factor as a new assignment.
    /// `None` if not authorized or no job is known yet.
    pub fn issue(&mut self, now_secs: f64) -> Option<Assignment> {
        if self.state != SessionState::Authorized {
            return None;
        }
        let job = self.latest_job.clone()?;
        let clean = self
            .assignments
            .back()
            .is_none_or(|a| a.job.height != job.height);
        let assignment = Assignment {
            id: self.next_assignment_id,
            job,
            factor: self.vardiff.factor(),
            clean,
        };
        self.next_assignment_id += 1;
        self.assignments.push_back(assignment.clone());
        while self.assignments.len() > RECENT_ASSIGNMENTS {
            self.assignments.pop_front();
        }
        self.retarget_pending = false;
        self.vardiff.start(now_secs);
        Some(assignment)
    }

    /// Periodic housekeeping (call every few seconds): lets vardiff ease a worker
    /// that has gone quiet. Pair with [`Session::take_retarget`].
    pub fn tick(&mut self, now_secs: f64) {
        if self.state == SessionState::Authorized
            && !self.assignments.is_empty()
            && self.vardiff.on_tick(now_secs)
        {
            self.retarget_pending = true;
        }
    }

    /// If vardiff moved since the last assignment, issue the current job again at
    /// the new factor (`clean = false`: the miner may finish in-flight work,
    /// which stays gradeable at its original boundary).
    pub fn take_retarget(&mut self, now_secs: f64) -> Option<Assignment> {
        if !self.retarget_pending {
            return None;
        }
        self.issue(now_secs)
    }

    /// Handle `mining.submit`: classify a full `nonce` for assignment `job_id` at
    /// monotonic time `now_secs`. Credits on accept; rejects
    /// stale/out-of-lane/duplicate/low.
    pub fn submit(&mut self, job_id: u64, nonce: [u8; 8], now_secs: f64) -> SubmitOutcome {
        if self.state != SessionState::Authorized {
            return self.reject(RejectReason::NotAuthorized);
        }
        let current_height = match &self.latest_job {
            Some(j) => j.height,
            None => return self.reject(RejectReason::StaleJob),
        };
        // Any retained assignment at the current height is live work.
        let (job, factor) = match self.assignment(job_id) {
            Some(a) if a.job.height == current_height => (a.job.clone(), a.factor),
            _ => return self.reject(RejectReason::StaleJob),
        };
        // The full nonce must lie in this connection's assigned lane.
        if !self.extra_nonce.contains(&nonce) {
            return self.reject(RejectReason::WrongLane);
        }
        // Replay / double-credit guard, before spending PoW on a known nonce.
        if self.seen.contains(&(job.msg, nonce)) {
            return self.reject(RejectReason::DuplicateShare);
        }
        // Grade at the factor THIS assignment advertised.
        let class = classify(&job.submission(nonce), factor);
        self.credit(&job, nonce, factor, class, now_secs)
    }

    /// The post-classification state transition shared by production and tests:
    /// credit + remember + feed vardiff on a valid share, reject below-target.
    /// Split out so the accept/block/weight/vardiff paths are deterministically
    /// testable without forging a real Autolykos2 solution. Assumes the lane +
    /// stale + duplicate guards in [`Session::submit`] already passed.
    fn credit(
        &mut self,
        job: &Job,
        nonce: [u8; 8],
        factor: u64,
        class: ShareClass,
        now_secs: f64,
    ) -> SubmitOutcome {
        if class == ShareClass::BelowTarget {
            return self.reject(RejectReason::BelowTarget);
        }
        self.seen.insert((job.msg, nonce));
        let weight = share_weight(&job.target, factor);
        if self.vardiff.on_share(now_secs) {
            self.retarget_pending = true;
        }
        self.stats.accepted += 1;
        if class == ShareClass::Block {
            self.stats.blocks += 1;
            SubmitOutcome::Block {
                weight,
                height: job.height,
            }
        } else {
            SubmitOutcome::Accepted {
                weight,
                height: job.height,
            }
        }
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

    use crate::vardiff::RETARGET_SHARES;

    // A hard target so an arbitrary nonce classifies BelowTarget under the real
    // consensus PoW — lets us exercise reject paths without a genuine solution.
    fn hard_target() -> BigUint {
        get_target(0x1b00_ffff)
    }

    fn job_at(id: u64, msg_seed: u8, height: u32, target: BigUint) -> Job {
        Job {
            id,
            msg: [msg_seed; 32],
            height,
            version: 3,
            target,
        }
    }

    fn hard_job(id: u64) -> Job {
        job_at(id, 0, 1_786_189, hard_target())
    }

    fn vd() -> VarDiff {
        VarDiff::new(1000, 10.0, 1, 100_000)
    }

    // Tests drive the whole-space lane so any nonce is in-lane; the lane gate has
    // its own focused test below.
    fn authed_with(vd: VarDiff) -> Session {
        let mut s = Session::new(ExtraNonce::whole(), vd);
        s.subscribe();
        assert!(s.authorize("miner.worker1"));
        s
    }

    fn authed() -> Session {
        authed_with(vd())
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
    fn reauthorizing_keeps_the_identity_fixed() {
        let mut s = authed();
        assert!(
            s.authorize("miner.worker1"),
            "same name again is idempotent"
        );
        assert!(!s.authorize("someone.else"), "a different name is refused");
        assert_eq!(s.worker(), Some("miner.worker1"));
        assert_eq!(s.state(), SessionState::Authorized);
    }

    #[test]
    fn agent_is_sanitized_capped_and_used_to_spot_nicehash() {
        let mut s = Session::new(ExtraNonce::whole(), vd());
        assert_eq!(s.agent(), None);
        assert!(!s.is_nicehash());
        s.set_agent("Rigel/1.23.2\n\u{7}");
        assert_eq!(s.agent(), Some("Rigel/1.23.2"));
        s.set_agent(&"x".repeat(500));
        assert_eq!(s.agent().map(str::len), Some(MAX_AGENT_LEN));
        s.set_agent("NiceHash/1.0.0");
        assert!(s.is_nicehash());
        s.set_agent("\n");
        assert_eq!(s.agent(), None, "nothing printable -> no agent");
    }

    #[test]
    fn subscribe_does_not_downgrade_authorized() {
        let mut s = authed();
        s.subscribe();
        assert_eq!(s.state(), SessionState::Authorized);
    }

    // ----- assignments -----
    #[test]
    fn job_before_authorize_is_remembered_and_issued_after() {
        let mut s = Session::new(ExtraNonce::whole(), vd());
        s.subscribe();
        assert!(
            s.assign_job(hard_job(1), 0.0).is_none(),
            "not authorized yet"
        );
        assert!(s.authorize("w"));
        let a = s.issue(0.0).expect("remembered job is issued on authorize");
        assert_eq!(a.id, 1);
        assert!(a.clean, "a connection's first assignment is clean");
        assert_eq!(a.factor, 1000);
    }

    #[test]
    fn clean_only_when_the_height_changes() {
        let mut s = authed();
        let a1 = s
            .assign_job(job_at(1, 0xA, 100, hard_target()), 0.0)
            .unwrap();
        let a2 = s
            .assign_job(job_at(2, 0xB, 100, hard_target()), 1.0)
            .unwrap();
        let a3 = s
            .assign_job(job_at(3, 0xC, 101, hard_target()), 2.0)
            .unwrap();
        assert!(a1.clean);
        assert!(
            !a2.clean,
            "same-height template refresh must not restart miners"
        );
        assert!(a3.clean, "new height must");
        assert_eq!((a1.id, a2.id, a3.id), (1, 2, 3));
    }

    #[test]
    fn assignment_boundary_is_target_times_its_own_factor() {
        let mut s = authed();
        let a = s.assign_job(hard_job(1), 0.0).unwrap();
        assert_eq!(a.boundary(), hard_target() * BigUint::from(1000u64));
        assert_eq!(s.share_target(), Some(a.boundary()));
    }

    // ----- submit gating / anti-cheat -----
    #[test]
    fn submit_before_authorize_is_rejected() {
        let mut s = Session::new(ExtraNonce::whole(), vd());
        s.subscribe();
        s.assign_job(hard_job(1), 0.0);
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
    fn submit_for_unknown_assignment_is_stale() {
        let mut s = authed();
        s.assign_job(hard_job(1), 0.0);
        assert_eq!(
            s.submit(99, [0u8; 8], 0.0),
            SubmitOutcome::Rejected(RejectReason::StaleJob)
        );
    }

    #[test]
    fn work_for_an_older_height_is_stale() {
        let mut s = authed();
        let old = s
            .assign_job(job_at(1, 0xA, 100, hard_target()), 0.0)
            .unwrap();
        s.assign_job(job_at(2, 0xB, 101, hard_target()), 1.0); // new block
        assert_eq!(
            s.submit(old.id, [0u8; 8], 2.0),
            SubmitOutcome::Rejected(RejectReason::StaleJob)
        );
        assert_eq!(s.stats().stale, 1);
    }

    #[test]
    fn previous_template_at_the_same_height_is_still_graded() {
        // The node publishes an early template then a refreshed one at the same
        // height and accepts solutions for both; a late share for the first must
        // be graded (here: BelowTarget on the hard target), NOT thrown away stale.
        let mut s = authed();
        let first = s
            .assign_job(job_at(1, 0xA, 100, hard_target()), 0.0)
            .unwrap();
        s.assign_job(job_at(2, 0xB, 100, hard_target()), 1.0);
        assert_eq!(
            s.submit(first.id, [0u8; 8], 2.0),
            SubmitOutcome::Rejected(RejectReason::BelowTarget)
        );
        assert_eq!(s.stats().stale, 0);
    }

    #[test]
    fn assignments_older_than_the_retention_window_are_stale() {
        let mut s = authed();
        let first = s.assign_job(job_at(1, 0, 100, hard_target()), 0.0).unwrap();
        for i in 0..RECENT_ASSIGNMENTS as u64 {
            s.assign_job(job_at(2 + i, (i + 1) as u8, 100, hard_target()), 1.0);
        }
        assert!(s.assignment(first.id).is_none());
        assert_eq!(
            s.submit(first.id, [0u8; 8], 2.0),
            SubmitOutcome::Rejected(RejectReason::StaleJob)
        );
    }

    #[test]
    fn out_of_lane_nonce_is_rejected_before_pow() {
        // A 4-byte lane 0x11223344: a nonce with a different prefix is another
        // worker's slice and must be rejected WrongLane.
        let mut s = Session::new(ExtraNonce::from_lane(0x1122_3344, 4), vd());
        s.subscribe();
        assert!(s.authorize("miner.worker1"));
        let a = s.assign_job(hard_job(1), 0.0).unwrap();
        let out = s.submit(a.id, [0x99, 0x99, 0x99, 0x99, 0, 0, 0, 1], 0.0);
        assert_eq!(out, SubmitOutcome::Rejected(RejectReason::WrongLane));
        assert_eq!(s.stats().wrong_lane, 1);
        // An in-lane nonce passes the lane gate (then fails on the hard target).
        let out = s.submit(a.id, [0x11, 0x22, 0x33, 0x44, 0, 0, 0, 1], 0.0);
        assert_eq!(out, SubmitOutcome::Rejected(RejectReason::BelowTarget));
    }

    #[test]
    fn below_target_solution_is_rejected_not_credited() {
        let mut s = authed();
        let a = s.assign_job(hard_job(1), 0.0).unwrap();
        assert_eq!(
            s.submit(a.id, [0u8; 8], 0.0),
            SubmitOutcome::Rejected(RejectReason::BelowTarget)
        );
        assert_eq!(s.stats().accepted, 0);
        assert_eq!(s.stats().low_diff, 1);
    }

    #[test]
    fn below_target_share_is_not_remembered_so_it_regrades() {
        let mut s = authed();
        let a = s.assign_job(hard_job(1), 0.0).unwrap();
        assert_eq!(
            s.submit(a.id, [9u8; 8], 0.0),
            SubmitOutcome::Rejected(RejectReason::BelowTarget)
        );
        assert_eq!(
            s.submit(a.id, [9u8; 8], 1.0),
            SubmitOutcome::Rejected(RejectReason::BelowTarget)
        );
        assert_eq!(s.stats().duplicate, 0);
    }

    // ----- grading at the ASSIGNED factor (real PoW) -----
    //
    // With network target 2^240, any share factor >= 2^16 puts the share target at
    // or past 2^256, so EVERY real Autolykos2 hit is a valid share (or, 1 in 2^16,
    // a block) — a deterministic accept without forging a solution.
    fn always_share_target() -> BigUint {
        BigUint::from(1u8) << 240
    }

    #[test]
    fn shares_are_graded_and_weighted_at_their_assignments_factor() {
        let mut s = authed_with(VarDiff::new(100_000, 15.0, 1, 1_000_000));
        let target = always_share_target();
        let first = s
            .assign_job(job_at(1, 7, 100, target.clone()), 0.0)
            .unwrap();
        assert_eq!(first.factor, 100_000);

        // A burst of fast accepts drives vardiff 4x harder...
        for i in 0..RETARGET_SHARES {
            let out = s.submit(first.id, [i as u8, 1, 0, 0, 0, 0, 0, 0], 0.1 * f64::from(i));
            assert!(matches!(
                out,
                SubmitOutcome::Accepted { .. } | SubmitOutcome::Block { .. }
            ));
        }
        assert_eq!(s.factor(), 25_000, "vardiff moved");

        // ...but a late share for the FIRST assignment is still graded and
        // weighted at the 100k it was advertised at, not the new 25k.
        match s.submit(first.id, [0xEE, 2, 0, 0, 0, 0, 0, 0], 1.0) {
            SubmitOutcome::Accepted { weight, height }
            | SubmitOutcome::Block { weight, height } => {
                assert_eq!(weight, share_weight(&target, 100_000));
                assert_eq!(height, 100);
            }
            other => panic!("expected accept, got {other:?}"),
        }

        // The miner is re-advertised at the new difficulty under a fresh id,
        // without being told to drop its work.
        let next = s
            .take_retarget(1.0)
            .expect("retarget delivers a new assignment");
        assert_eq!(next.factor, 25_000);
        assert!(!next.clean);
        assert_ne!(next.id, first.id);
        assert!(s.take_retarget(1.0).is_none(), "delivered once");
    }

    #[test]
    fn idle_worker_is_eased_and_re_advertised_on_tick() {
        let mut s = authed_with(VarDiff::new(1000, 15.0, 1, 1_000_000));
        s.assign_job(hard_job(1), 0.0);
        s.tick(60.0);
        assert!(s.take_retarget(60.0).is_none(), "window still open");
        s.tick(120.0);
        let a = s
            .take_retarget(120.0)
            .expect("quiet window eases difficulty");
        assert_eq!(a.factor, 4000);
        assert!(!a.clean);
    }

    #[test]
    fn duplicate_is_caught_across_a_difficulty_re_advertisement() {
        // Dedup is keyed by template msg, not assignment id: re-advertising the
        // same template at a new factor must not reopen an accepted nonce.
        let mut s = authed_with(VarDiff::new(100_000, 15.0, 1, 1_000_000));
        let target = always_share_target();
        let a = s.assign_job(job_at(1, 7, 100, target), 0.0).unwrap();
        let nonce = [5u8; 8];
        assert!(!matches!(
            s.submit(a.id, nonce, 0.0),
            SubmitOutcome::Rejected(_)
        ));
        let b = s.issue(1.0).unwrap(); // same template, new assignment id
        assert_eq!(
            s.submit(b.id, nonce, 1.0),
            SubmitOutcome::Rejected(RejectReason::DuplicateShare)
        );
        assert_eq!(s.stats().duplicate, 1);
    }

    // ----- accept / block / weight via the `credit` seam -----
    #[test]
    fn credited_share_is_accepted_with_positive_weight_and_remembered() {
        let mut s = authed();
        let a = s.assign_job(hard_job(1), 0.0).unwrap();
        let out = s.credit(&a.job, [3u8; 8], a.factor, ShareClass::Share, 0.0);
        match out {
            SubmitOutcome::Accepted { weight, .. } => assert!(weight >= 1),
            other => panic!("expected Accepted, got {other:?}"),
        }
        assert_eq!(s.stats().accepted, 1);
        // Now a real submit of the SAME (template, nonce) hits the dedup guard.
        assert_eq!(
            s.submit(a.id, [3u8; 8], 1.0),
            SubmitOutcome::Rejected(RejectReason::DuplicateShare)
        );
        assert_eq!(s.stats().duplicate, 1);
    }

    #[test]
    fn credited_block_counts_as_block_and_share() {
        let mut s = authed();
        let a = s.assign_job(hard_job(1), 0.0).unwrap();
        let out = s.credit(&a.job, [4u8; 8], a.factor, ShareClass::Block, 0.0);
        assert!(matches!(out, SubmitOutcome::Block { weight, height: 1_786_189 } if weight >= 1));
        assert_eq!(s.stats().blocks, 1);
        assert_eq!(s.stats().accepted, 1, "a block is also a counted share");
    }

    #[test]
    fn new_height_clears_seen_so_a_recycled_nonce_is_not_blocked() {
        let mut s = authed();
        let a = s.assign_job(job_at(1, 0, 100, hard_target()), 0.0).unwrap();
        s.credit(&a.job, [5u8; 8], a.factor, ShareClass::Share, 0.0);
        let b = s.assign_job(job_at(2, 0, 101, hard_target()), 1.0).unwrap();
        // Same msg seed, new height: the set was cleared, so the nonce accepts.
        let out = s.credit(&b.job, [5u8; 8], b.factor, ShareClass::Share, 1.0);
        assert!(matches!(out, SubmitOutcome::Accepted { .. }));
    }

    #[test]
    fn same_height_refresh_keeps_seen_to_block_double_credit() {
        let mut s = authed();
        let a = s.assign_job(hard_job(7), 0.0).unwrap();
        s.credit(&a.job, [6u8; 8], a.factor, ShareClass::Share, 0.0);
        // Re-send the SAME template (a refresh) — dedup history must survive.
        let b = s.assign_job(hard_job(7), 1.0).unwrap();
        assert_eq!(
            s.submit(b.id, [6u8; 8], 1.0),
            SubmitOutcome::Rejected(RejectReason::DuplicateShare)
        );
    }
}
