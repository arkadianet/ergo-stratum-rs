//! Per-worker variable difficulty (vardiff).
//!
//! The pool sets each worker an easier-than-network share difficulty so it
//! submits shares at a steady cadence (PPLNS needs a usable share rate without
//! flooding). We track the share difficulty as a `factor` (`share_target =
//! network_target * factor`; bigger factor = easier = more frequent shares) and
//! nudge it toward a target inter-share interval.

/// A per-worker vardiff controller. Pure + deterministic; the session layer feeds
/// it the observed time between accepted shares.
#[derive(Clone, Debug)]
pub struct VarDiff {
    factor: u64,
    target_interval_secs: f64,
    min_factor: u64,
    max_factor: u64,
}

impl VarDiff {
    /// `initial` share factor; aim for ~one share every `target_interval_secs`;
    /// clamp the factor to `[min_factor, max_factor]`.
    pub fn new(initial: u64, target_interval_secs: f64, min_factor: u64, max_factor: u64) -> Self {
        let min_factor = min_factor.max(1);
        let max_factor = max_factor.max(min_factor);
        Self {
            factor: initial.clamp(min_factor, max_factor),
            target_interval_secs: target_interval_secs.max(0.001),
            min_factor,
            max_factor,
        }
    }

    /// Current share factor (`share_target = network_target * factor`).
    pub fn factor(&self) -> u64 {
        self.factor
    }

    /// Feed the observed seconds since this worker's last accepted share. Returns
    /// the (possibly retargeted) factor. Shares arriving too fast -> harder
    /// (lower factor); too slow -> easier (higher factor). Retargets only on a
    /// meaningful deviation and clamps the per-step swing to 4x to avoid thrash.
    pub fn observe(&mut self, since_last_secs: f64) -> u64 {
        if since_last_secs <= 0.0 {
            return self.factor;
        }
        let ratio = since_last_secs / self.target_interval_secs;
        if !(0.66..=1.5).contains(&ratio) {
            let step = ratio.clamp(0.25, 4.0);
            let next = (self.factor as f64 * step).round().max(1.0) as u64;
            self.factor = next.clamp(self.min_factor, self.max_factor);
        }
        self.factor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----
    #[test]
    fn on_target_interval_leaves_factor_unchanged() {
        let mut vd = VarDiff::new(1000, 10.0, 1, 100_000);
        assert_eq!(vd.observe(10.0), 1000);
        assert_eq!(vd.observe(11.0), 1000); // within the dead-band
    }

    #[test]
    fn too_slow_makes_it_easier_higher_factor() {
        let mut vd = VarDiff::new(1000, 10.0, 1, 100_000);
        let f = vd.observe(40.0); // 4x too slow
        assert!(f > 1000, "should raise the factor, got {f}");
    }

    #[test]
    fn too_fast_makes_it_harder_lower_factor() {
        let mut vd = VarDiff::new(1000, 10.0, 1, 100_000);
        let f = vd.observe(2.0); // 5x too fast
        assert!(f < 1000, "should lower the factor, got {f}");
    }

    // ----- bounds / edges -----
    #[test]
    fn factor_is_clamped_to_bounds() {
        let mut vd = VarDiff::new(100, 10.0, 50, 200);
        for _ in 0..20 {
            vd.observe(1000.0); // relentlessly too slow
        }
        assert_eq!(vd.factor(), 200, "clamps at max");
        for _ in 0..20 {
            vd.observe(0.001); // relentlessly too fast
        }
        assert_eq!(vd.factor(), 50, "clamps at min");
    }

    #[test]
    fn nonpositive_interval_is_ignored() {
        let mut vd = VarDiff::new(1000, 10.0, 1, 100_000);
        assert_eq!(vd.observe(0.0), 1000);
        assert_eq!(vd.observe(-5.0), 1000);
    }

    #[test]
    fn per_step_swing_is_capped_at_4x() {
        let mut vd = VarDiff::new(1000, 10.0, 1, 100_000);
        let f = vd.observe(10_000.0); // 1000x too slow, but step capped at 4x
        assert_eq!(f, 4000);
    }
}
