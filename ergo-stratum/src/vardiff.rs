//! Per-worker variable difficulty (vardiff).
//!
//! The pool sets each worker an easier-than-network share difficulty so it
//! submits shares at a steady cadence (enough to measure hashrate without
//! flooding). We track the share difficulty as a `factor` (`share_target =
//! network_target * factor`; bigger factor = easier = more frequent shares) and
//! nudge it toward a target inter-share interval.
//!
//! Share arrivals are a Poisson process, so a *single* inter-share gap is far too
//! noisy to act on (~70% of gaps fall outside a ±50% band even for a perfectly
//! tuned worker). The controller therefore judges the **average** rate over a
//! window: it re-evaluates after [`RETARGET_SHARES`] accepted shares, or after the
//! same number of target intervals has elapsed — whichever comes first. The time
//! trigger is what rescues a worker whose difficulty is far too hard: with zero
//! shares in the window it still gets easier work instead of waiting forever.

/// Accepted shares to collect before judging the rate.
pub const RETARGET_SHARES: u32 = 8;

/// Largest per-evaluation swing (either direction).
const MAX_STEP: f64 = 4.0;

/// Observed/target interval ratios inside this band are left alone. With 8
/// shares the windowed mean has ~35% relative noise, so this band keeps a
/// well-tuned worker from retargeting on noise (~6% of windows).
const DEAD_BAND: std::ops::RangeInclusive<f64> = 0.5..=2.0;

/// A per-worker vardiff controller. Pure + deterministic; the session layer feeds
/// it accepted shares and periodic ticks with an injected monotonic clock.
#[derive(Clone, Debug)]
pub struct VarDiff {
    factor: u64,
    target_interval_secs: f64,
    min_factor: u64,
    max_factor: u64,
    /// Start of the current measurement window (`None` until the worker is first
    /// handed work).
    window_start: Option<f64>,
    /// Accepted shares in the current window.
    window_shares: u32,
}

impl VarDiff {
    /// `initial` share factor; aim for ~one share every `target_interval_secs`;
    /// clamp the factor to `[min_factor, max_factor]`.
    pub fn new(initial: u64, target_interval_secs: f64, min_factor: u64, max_factor: u64) -> Self {
        let min_factor = min_factor.max(1);
        let max_factor = max_factor.max(min_factor);
        let target_interval_secs = if target_interval_secs.is_finite() {
            target_interval_secs.max(0.001)
        } else {
            15.0
        };
        Self {
            factor: initial.clamp(min_factor, max_factor),
            target_interval_secs,
            min_factor,
            max_factor,
            window_start: None,
            window_shares: 0,
        }
    }

    /// Current share factor (`share_target = network_target * factor`).
    pub fn factor(&self) -> u64 {
        self.factor
    }

    /// Open the measurement window at `now` if it isn't open yet (the worker was
    /// just handed its first work). Idempotent.
    pub fn start(&mut self, now: f64) {
        if self.window_start.is_none() {
            self.window_start = Some(now);
            self.window_shares = 0;
        }
    }

    /// Record one accepted share at `now`. Returns `true` if the factor changed
    /// (the caller must re-advertise the new difficulty to the miner).
    pub fn on_share(&mut self, now: f64) -> bool {
        if self.window_start.is_none() {
            // No window yet: this share only anchors the clock.
            self.start(now);
            return false;
        }
        self.window_shares += 1;
        if self.window_shares >= RETARGET_SHARES {
            return self.evaluate(now);
        }
        self.on_tick(now)
    }

    /// Periodic check with no share required. Once a full window has elapsed the
    /// rate is judged on whatever arrived — including nothing, which eases the
    /// difficulty. Returns `true` if the factor changed.
    pub fn on_tick(&mut self, now: f64) -> bool {
        match self.window_start {
            None => {
                self.start(now);
                false
            }
            Some(start) if now - start >= self.window_secs() => self.evaluate(now),
            Some(_) => false,
        }
    }

    fn window_secs(&self) -> f64 {
        self.target_interval_secs * f64::from(RETARGET_SHARES)
    }

    /// Judge the closing window and start a new one at `now`.
    fn evaluate(&mut self, now: f64) -> bool {
        let start = self.window_start.unwrap_or(now);
        let elapsed = (now - start).max(0.0);
        let shares = self.window_shares;
        self.window_start = Some(now);
        self.window_shares = 0;

        // Observed / target interval: > 1 is too slow (make easier), < 1 too fast.
        let ratio = if shares == 0 {
            MAX_STEP
        } else {
            elapsed / f64::from(shares) / self.target_interval_secs
        };
        if DEAD_BAND.contains(&ratio) {
            return false;
        }
        let step = ratio.clamp(1.0 / MAX_STEP, MAX_STEP);
        // `as u64` saturates, so an absurd product can't wrap.
        let next = (self.factor as f64 * step).round().max(1.0) as u64;
        let next = next.clamp(self.min_factor, self.max_factor);
        let changed = next != self.factor;
        self.factor = next;
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `n` shares spaced `gap` seconds apart starting after `t0`; returns the
    /// time of the last share and whether any of them changed the factor.
    fn shares(vd: &mut VarDiff, t0: f64, n: u32, gap: f64) -> (f64, bool) {
        let mut t = t0;
        let mut changed = false;
        for _ in 0..n {
            t += gap;
            changed |= vd.on_share(t);
        }
        (t, changed)
    }

    // ----- happy path -----
    #[test]
    fn on_target_rate_leaves_factor_unchanged() {
        let mut vd = VarDiff::new(1000, 15.0, 1, 100_000);
        vd.start(0.0);
        let (_, changed) = shares(&mut vd, 0.0, 16, 15.0);
        assert!(!changed);
        assert_eq!(vd.factor(), 1000);
    }

    #[test]
    fn modest_noise_inside_the_dead_band_is_ignored() {
        // 8 shares averaging 22s against a 15s target (ratio ~1.47) — within the
        // dead band, so no retarget on what is plausibly just Poisson noise.
        let mut vd = VarDiff::new(1000, 15.0, 1, 100_000);
        vd.start(0.0);
        let (_, changed) = shares(&mut vd, 0.0, 8, 22.0);
        assert!(!changed);
        assert_eq!(vd.factor(), 1000);
    }

    #[test]
    fn too_fast_makes_it_harder_lower_factor() {
        let mut vd = VarDiff::new(1000, 15.0, 1, 100_000);
        vd.start(0.0);
        // 8 shares in 8s against a 15s target: ~15x too fast, step capped at 4x.
        let (_, changed) = shares(&mut vd, 0.0, 8, 1.0);
        assert!(changed);
        assert_eq!(vd.factor(), 250);
    }

    #[test]
    fn too_slow_makes_it_easier_higher_factor() {
        let mut vd = VarDiff::new(1000, 15.0, 1, 100_000);
        vd.start(0.0);
        // Two shares in a full 120s window: 60s/share vs 15s target -> 4x easier.
        assert!(!vd.on_share(30.0));
        assert!(!vd.on_share(60.0));
        assert!(vd.on_tick(120.0));
        assert_eq!(vd.factor(), 4000);
    }

    #[test]
    fn an_idle_worker_is_eased_without_any_share() {
        // The old per-share controller could never rescue a worker that found no
        // share at all; the windowed one eases it on the clock alone.
        let mut vd = VarDiff::new(1000, 15.0, 1, 100_000);
        vd.start(0.0);
        assert!(!vd.on_tick(119.0), "window not elapsed yet");
        assert!(vd.on_tick(120.0));
        assert_eq!(vd.factor(), 4000);
        assert!(vd.on_tick(240.0));
        assert_eq!(vd.factor(), 16_000);
    }

    // ----- bounds / edges -----
    #[test]
    fn factor_is_clamped_to_bounds_and_reports_no_change_at_the_bound() {
        let mut vd = VarDiff::new(100, 15.0, 50, 200);
        vd.start(0.0);
        assert!(vd.on_tick(120.0));
        assert_eq!(vd.factor(), 200, "clamps at max");
        assert!(!vd.on_tick(240.0), "already at max: no change to advertise");
        let (_, _) = shares(&mut vd, 240.0, 8, 0.01);
        let (_, _) = shares(&mut vd, 300.0, 8, 0.01);
        assert_eq!(vd.factor(), 50, "clamps at min");
    }

    #[test]
    fn first_share_before_start_only_anchors_the_window() {
        let mut vd = VarDiff::new(1000, 15.0, 1, 100_000);
        assert!(!vd.on_share(5.0));
        assert_eq!(vd.factor(), 1000);
        // The window opened at t=5, so it closes at t=125, not t=120.
        assert!(!vd.on_tick(124.0));
        assert!(vd.on_tick(125.0));
    }

    #[test]
    fn start_is_idempotent() {
        let mut vd = VarDiff::new(1000, 15.0, 1, 100_000);
        vd.start(0.0);
        vd.start(100.0); // must not push the window forward
        assert!(vd.on_tick(120.0));
    }

    #[test]
    fn nonfinite_interval_falls_back_to_a_sane_default() {
        let mut vd = VarDiff::new(1000, f64::NAN, 1, 100_000);
        vd.start(0.0);
        assert!(!vd.on_tick(60.0));
        assert!(vd.on_tick(120.0));
    }
}
