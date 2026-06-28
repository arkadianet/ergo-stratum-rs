//! Autolykos2 share validation, reusing the node's consensus PoW.
//!
//! A pool job is the node's mining candidate: a 32-byte `msg`, the network
//! `target` (the candidate's `b`), and the `height`/`version` that fix the
//! Autolykos2 table size. A miner submits an 8-byte `nonce`. We compute the
//! consensus PoW hit and classify it against the network target (block) and the
//! easier pool share target (`target * share_factor`).

use num_bigint::BigUint;

use ergo_crypto::autolykos::common::calc_n;
use ergo_crypto::autolykos::v2::hit_for_v2;

/// A miner-submitted Autolykos2 solution against a pool job.
#[derive(Clone, Debug)]
pub struct Submission {
    /// The candidate message to solve (node `/mining/candidate` `msg`).
    pub msg: [u8; 32],
    /// The submitted nonce.
    pub nonce: [u8; 8],
    /// Candidate height (sets the Autolykos2 table size N).
    pub height: u32,
    /// Block version (Autolykos v1 vs v2 table rules).
    pub version: u8,
    /// Network target `b` (a real block needs `hit <= target`).
    pub target: BigUint,
}

/// Where a submission falls relative to the network and pool-share targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareClass {
    /// `hit <= network_target` — a real block. Submit it to the node.
    Block,
    /// `network_target < hit <= share_target` — a valid pool share (counts).
    Share,
    /// `hit > share_target` — below the pool's share difficulty. Reject.
    BelowTarget,
}

/// Pure threshold classification given a computed `hit` and the network target.
/// `share_factor` (>= 1) makes the share target easier:
/// `share_target = network_target * share_factor`.
pub fn classify_hit(hit: &BigUint, network_target: &BigUint, share_factor: u64) -> ShareClass {
    if hit <= network_target {
        return ShareClass::Block;
    }
    let share_target = network_target * BigUint::from(share_factor.max(1));
    if hit <= &share_target {
        ShareClass::Share
    } else {
        ShareClass::BelowTarget
    }
}

/// Validate + classify a submission, computing the consensus Autolykos2 hit via
/// `ergo-crypto` (the exact path the node uses in `verify_solution`).
pub fn classify(sub: &Submission, share_factor: u64) -> ShareClass {
    let n = calc_n(sub.version, sub.height);
    let hit = hit_for_v2(&sub.msg, &sub.nonce, sub.height, n);
    classify_hit(&hit, &sub.target, share_factor)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ergo_crypto::difficulty::get_target;

    fn big(n: u64) -> BigUint {
        BigUint::from(n)
    }

    // ----- happy path: pure threshold logic -----
    #[test]
    fn hit_at_or_below_network_target_is_a_block() {
        assert_eq!(classify_hit(&big(5), &big(10), 100), ShareClass::Block);
        assert_eq!(classify_hit(&big(10), &big(10), 100), ShareClass::Block); // boundary inclusive
    }

    #[test]
    fn hit_within_share_band_is_a_share() {
        // target 10, factor 10 -> share_target 100. hit 50 is a share.
        assert_eq!(classify_hit(&big(50), &big(10), 10), ShareClass::Share);
        assert_eq!(classify_hit(&big(100), &big(10), 10), ShareClass::Share); // boundary inclusive
    }

    #[test]
    fn hit_above_share_target_is_rejected() {
        assert_eq!(
            classify_hit(&big(101), &big(10), 10),
            ShareClass::BelowTarget
        );
    }

    // ----- error paths / edges -----
    #[test]
    fn share_factor_one_collapses_share_band_to_block_or_reject() {
        // factor 1 -> share_target == network_target; nothing is a Share.
        assert_eq!(classify_hit(&big(10), &big(10), 1), ShareClass::Block);
        assert_eq!(classify_hit(&big(11), &big(10), 1), ShareClass::BelowTarget);
    }

    #[test]
    fn share_factor_zero_is_treated_as_one() {
        assert_eq!(classify_hit(&big(11), &big(10), 0), ShareClass::BelowTarget);
    }

    // ----- ergo-crypto integration: the consensus PoW path runs -----
    #[test]
    fn classify_runs_the_consensus_pow_and_rejects_a_nonwinning_nonce() {
        // An all-zero nonce on mainnet-class difficulty cannot meet a sane share
        // target — this exercises calc_n + hit_for_v2 end-to-end.
        let sub = Submission {
            msg: [0u8; 32],
            nonce: [0u8; 8],
            height: 1_786_189,
            version: 3,
            target: get_target(0x1b00_ffff), // hard target
        };
        assert_eq!(classify(&sub, 1_000), ShareClass::BelowTarget);
    }
}
