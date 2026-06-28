//! Pool jobs (derived from the node mining candidate) and PPLNS share weighting.
//!
//! A [`Job`] is one unit of work the pool hands miners: the node candidate `msg`
//! plus the height/version that fix the Autolykos2 table, the **network target**
//! `b` the candidate already carries (decimal big-int from `/mining/candidate`,
//! parsed straight into a [`BigUint`] — no `nBits` round-trip), a pool-assigned
//! `id`, and a `clean` flag (a fresh block template that obsoletes prior jobs).
//! [`share_weight`] turns an accepted share into the difficulty it represents, so
//! the M2 accountant weights work fairly across miners at different vardiff
//! factors.

use num_bigint::BigUint;

use crate::share::Submission;

/// A unit of work handed to a miner. Mirrors the node `/mining/candidate` fields
/// the share validator needs, plus pool job bookkeeping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    /// Pool-assigned, monotonically increasing job id.
    pub id: u64,
    /// The candidate message to solve (the node candidate `msg`).
    pub msg: [u8; 32],
    /// Candidate height (sets the Autolykos2 table size N).
    pub height: u32,
    /// Block version (Autolykos v1 vs v2 table rules).
    pub version: u8,
    /// Network target `b` (a real block needs `hit <= target`). Taken verbatim
    /// from the candidate — the easier per-worker share target is this scaled by
    /// the vardiff factor.
    pub target: BigUint,
    /// New block template: drop all previously-issued jobs once this is sent.
    pub clean: bool,
}

impl Job {
    /// Build the [`Submission`] for a miner-supplied `nonce` against this job.
    pub fn submission(&self, nonce: [u8; 8]) -> Submission {
        Submission {
            msg: self.msg,
            nonce,
            height: self.height,
            version: self.version,
            target: self.target.clone(),
        }
    }
}

/// The PPLNS weight of one accepted share found at vardiff `factor` against a job
/// with the given network `target`: the **share difficulty**
/// `2^256 / (target * factor)`.
///
/// A miner assigned an easier target (larger `factor`) finds shares more often but
/// each is worth proportionally less, so summed weight tracks real hashrate
/// regardless of each worker's assigned difficulty. The result is clamped to
/// `[1, u64::MAX]` so the accountant's `u128` window sum can never overflow.
pub fn share_weight(target: &BigUint, factor: u64) -> u128 {
    let denom = target * BigUint::from(factor.max(1));
    if denom == BigUint::ZERO {
        return 1;
    }
    let two_256 = BigUint::from(1u8) << 256;
    let w = two_256 / denom;
    u64::try_from(&w)
        .map(u128::from)
        .unwrap_or(u128::from(u64::MAX))
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ergo_crypto::difficulty::get_target;

    fn job(target: BigUint, clean: bool) -> Job {
        Job {
            id: 1,
            msg: [0xAB; 32],
            height: 1_500_000,
            version: 3,
            target,
            clean,
        }
    }

    #[test]
    fn submission_carries_job_fields_and_nonce() {
        let j = job(get_target(0x1b00_ffff), true);
        let s = j.submission([7u8; 8]);
        assert_eq!(s.msg, j.msg);
        assert_eq!(s.nonce, [7u8; 8]);
        assert_eq!(s.height, j.height);
        assert_eq!(s.version, j.version);
        assert_eq!(s.target, j.target);
    }

    // A moderate, Ergo-scale target: nBits 0x07100000 decodes to network
    // difficulty 0x100000 * 256^(7-3) = 2^20 * 2^32 = 2^52, so the target is
    // 2^256/2^52 = 2^204 and share difficulty 2^52/factor stays well within u64,
    // making proportionality observable. (0x1b00ffff encodes an absurd ~2^208
    // difficulty whose share weight saturates the u64 clamp — fine for "share is
    // rejected" tests, useless for weighting.)
    fn realistic_target() -> BigUint {
        get_target(0x0710_0000)
    }

    #[test]
    fn easier_factor_weighs_proportionally_less() {
        // share_weight ∝ 1/factor: doubling the factor halves the weight.
        let t = realistic_target();
        let w1 = share_weight(&t, 1000);
        let w2 = share_weight(&t, 2000);
        assert!(
            w1 > 0 && w2 > 0 && w1 < u128::from(u64::MAX),
            "no clamp: {w1} {w2}"
        );
        let ratio = w1 as f64 / w2 as f64;
        assert!((1.9..=2.1).contains(&ratio), "expected ~2x, got {ratio}");
    }

    #[test]
    fn weight_floors_to_one_when_factor_exceeds_difficulty() {
        // factor > network difficulty -> share difficulty < 1 -> clamps up to 1.
        assert_eq!(share_weight(&realistic_target(), u64::MAX), 1);
    }

    #[test]
    fn weight_never_exceeds_u64_max_for_safe_summation() {
        // An absurdly hard target would overflow share difficulty; the clamp keeps
        // it within u64 so the accountant's u128 window sum can't overflow.
        let w = share_weight(&get_target(0x1b00_ffff), 1);
        assert!(w <= u128::from(u64::MAX));
    }
}
