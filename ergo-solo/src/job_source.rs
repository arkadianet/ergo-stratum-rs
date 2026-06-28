//! Turn node mining candidates into pool [`Job`]s.
//!
//! The daemon polls `/mining/candidate` on a timer; most polls return the *same*
//! template. [`JobSource::make_job`] emits a fresh [`Job`] only when the candidate
//! message changes (new work), assigning a monotonically increasing job id. Every
//! emitted job is a new template, so it carries `clean = true` (miners drop prior
//! work and restart their nonce search).

use ergo_stratum::Job;

use crate::node::Candidate;

/// Stateful candidate → job converter (one per daemon).
pub struct JobSource {
    next_id: u64,
    last_msg: Option<[u8; 32]>,
    block_version: u8,
}

impl JobSource {
    /// New source stamping jobs with `block_version` (≥2 selects the v2 N
    /// schedule).
    pub fn new(block_version: u8) -> Self {
        Self {
            next_id: 1,
            last_msg: None,
            block_version,
        }
    }

    /// Emit a [`Job`] if `candidate` is new work (its `msg` differs from the last
    /// one issued); `None` if it is the same template we already handed out.
    pub fn make_job(&mut self, candidate: &Candidate) -> Option<Job> {
        if self.last_msg == Some(candidate.msg) {
            return None;
        }
        self.last_msg = Some(candidate.msg);
        let id = self.next_id;
        self.next_id += 1;
        Some(Job {
            id,
            msg: candidate.msg,
            height: candidate.height,
            version: self.block_version,
            target: candidate.target.clone(),
            clean: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn candidate(msg_seed: u8, height: u32) -> Candidate {
        Candidate {
            msg: [msg_seed; 32],
            target: BigUint::from(1_000u64),
            height,
            pk: None,
        }
    }

    #[test]
    fn first_candidate_emits_a_clean_job_with_id_one() {
        let mut src = JobSource::new(3);
        let j = src.make_job(&candidate(0xAA, 1000)).expect("new work");
        assert_eq!(j.id, 1);
        assert!(j.clean);
        assert_eq!(j.version, 3);
        assert_eq!(j.msg, [0xAA; 32]);
        assert_eq!(j.height, 1000);
        assert_eq!(j.target, BigUint::from(1_000u64));
    }

    #[test]
    fn unchanged_candidate_emits_nothing() {
        let mut src = JobSource::new(3);
        assert!(src.make_job(&candidate(0xAA, 1000)).is_some());
        assert!(src.make_job(&candidate(0xAA, 1000)).is_none());
        assert!(src.make_job(&candidate(0xAA, 1000)).is_none());
    }

    #[test]
    fn changed_message_emits_a_new_job_with_next_id() {
        let mut src = JobSource::new(3);
        let a = src.make_job(&candidate(0xAA, 1000)).unwrap();
        let b = src.make_job(&candidate(0xBB, 1001)).unwrap();
        assert_eq!(a.id, 1);
        assert_eq!(b.id, 2);
        assert_eq!(b.msg, [0xBB; 32]);
        assert!(b.clean);
    }

    #[test]
    fn returning_to_a_previous_message_still_counts_as_new_work() {
        // We only remember the *last* msg, so an A→B→A sequence re-issues A as a
        // fresh job (a miner must restart anyway after working B).
        let mut src = JobSource::new(3);
        src.make_job(&candidate(0xAA, 1000)).unwrap();
        src.make_job(&candidate(0xBB, 1001)).unwrap();
        let again = src.make_job(&candidate(0xAA, 1000)).unwrap();
        assert_eq!(again.id, 3);
    }
}
