#[allow(dead_code)]
pub(crate) const VAR_DIFF_THREAD_SLEEP: u64 = 10;
#[allow(dead_code)]
const WORK_WINDOW: u64 = 80;

// VarDiff tunables
const VARDIFF_MIN_ELAPSED_SECS: f64 = 30.0;
const VARDIFF_MAX_ELAPSED_SECS_NO_SHARES: f64 = 60.0;
const VARDIFF_MIN_SHARES: f64 = 3.0;
const VARDIFF_LOWER_RATIO: f64 = 0.75; // base lower threshold — expands downward over time
const VARDIFF_UPPER_RATIO: f64 = 1.25; // base upper threshold — expands upward over time
const VARDIFF_MAX_STEP_UP: f64 = 2.0;  // 1 pow2 step up per tick   (e.g. 512 → 1024)
const VARDIFF_MAX_STEP_DOWN: f64 = 0.5; // 1 pow2 step down per tick (e.g. 512 → 256)

/// Multiplier used exclusively by the forced-drop path (first-minute, no-share cascade).
/// 0.25 = 2 pow2 steps down per drop — more aggressive than normal vardiff step.
const VARDIFF_FORCED_DROP_MULTIPLIER: f64 = 0.25;

/// Absolute no-valid-share timeout for the early forced-drop path (first 120s only).
/// 60s without a valid share gives even a large miner at a high starting diff (e.g. 16384)
/// a full minute to find its first share before the drop fires.
pub(crate) const VARDIFF_NO_VALID_SHARE_SECS: f64 = 60.0;

/// Maximum number of forced drops allowed per worker (within the first 60s only).
/// One drop (2 pow2 steps via VARDIFF_FORCED_DROP_MULTIPLIER) is enough to unblock a
/// genuinely idle miner from an unreachable starting diff (e.g. 16384 → 4096).
/// Normal vardiff takes over from there for further calibration.  Capping at 1 avoids
/// over-shooting for large miners that were simply slow to produce their first share.
pub(crate) const VARDIFF_FORCED_DROP_MAX: u32 = 1;

fn vardiff_pow2_clamp_towards(current: f64, next: f64) -> f64 {
    if !next.is_finite() || next <= 0.0 {
        return 1.0;
    }

    let exp = if next >= current {
        next.log2().ceil()
    } else {
        next.log2().floor()
    };
    let clamped = 2_f64.powi(exp as i32);
    if clamped < 1.0 { 1.0 } else { clamped }
}

/// Compute the forced-drop difficulty when no valid share has arrived within
/// `VARDIFF_NO_VALID_SHARE_SECS` during the first 60s of a worker's session.
/// Uses `VARDIFF_FORCED_DROP_MULTIPLIER` (0.25 = 2 pow2 steps) — more aggressive than
/// the normal per-tick step — to rapidly bring a stuck new miner to a reachable diff.
///
/// Returns `None` if `current` is invalid or already at the floor (1.0), so the caller
/// can skip logging and still reset the window unconditionally.
pub(crate) fn vardiff_forced_drop(current: f64, clamp_pow2: bool) -> Option<f64> {
    if !current.is_finite() || current <= 0.0 {
        return None;
    }
    let mut next = (current * VARDIFF_FORCED_DROP_MULTIPLIER).max(1.0);
    if clamp_pow2 {
        next = vardiff_pow2_clamp_towards(current, next);
    }
    if (next - current).abs() > f64::EPSILON {
        Some(next)
    } else {
        None
    }
}

pub(crate) fn vardiff_compute_next_diff(
    current: f64,
    shares: f64,
    elapsed_secs: f64,
    expected_spm: f64,
    clamp_pow2: bool,
) -> Option<f64> {
    if !current.is_finite() || current <= 0.0 {
        return None;
    }
    if !elapsed_secs.is_finite() || elapsed_secs <= 0.0 {
        return None;
    }

    if shares == 0.0 && elapsed_secs >= VARDIFF_MAX_ELAPSED_SECS_NO_SHARES {
        let mut next = current * VARDIFF_MAX_STEP_DOWN;
        if next < 1.0 {
            next = 1.0;
        }
        if clamp_pow2 {
            next = vardiff_pow2_clamp_towards(current, next);
        }
        return if (next - current).abs() > f64::EPSILON {
            Some(next)
        } else {
            None
        };
    }

    if elapsed_secs < VARDIFF_MIN_ELAPSED_SECS || shares < VARDIFF_MIN_SHARES {
        return None;
    }

    let observed_spm = (shares / elapsed_secs) * 60.0;
    let ratio = observed_spm / expected_spm.max(1.0);
    if !ratio.is_finite() || ratio <= 0.0 {
        return None;
    }

    // Dead band expands symmetrically the longer the miner has been stable.
    // Every 30s past the minimum window adds ±5%, capped at ±15% extra (after 120s).
    //   elapsed=30s:  [0.75 – 1.25]
    //   elapsed=60s:  [0.70 – 1.30]
    //   elapsed=90s:  [0.65 – 1.35]
    //   elapsed=120s+:[0.60 – 1.40]
    let extra = ((elapsed_secs - VARDIFF_MIN_ELAPSED_SECS) / 30.0)
        .clamp(0.0, 3.0) * 0.05;
    let lower = VARDIFF_LOWER_RATIO - extra;
    let upper = VARDIFF_UPPER_RATIO + extra;
    if ratio > lower && ratio < upper {
        return None;
    }

    let step = ratio
        .sqrt()
        .clamp(VARDIFF_MAX_STEP_DOWN, VARDIFF_MAX_STEP_UP);
    let mut next = current * step;
    if next < 1.0 {
        next = 1.0;
    }
    if clamp_pow2 {
        next = vardiff_pow2_clamp_towards(current, next);
    }

    let rel_change = (next - current).abs() / current.max(1.0);
    if rel_change < 0.10 {
        return None;
    }
    if (next - current).abs() > f64::EPSILON {
        Some(next)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── vardiff_compute_next_diff ────────────────────────────────────────────

    #[test]
    fn no_shares_long_wait_lowers_diff() {
        // 95s > VARDIFF_MAX_ELAPSED_SECS_NO_SHARES (60s) with 0 shares → drop
        let next = vardiff_compute_next_diff(100.0, 0.0, 95.0, 10.0, false).expect("should adjust");
        assert!(next < 100.0);
        assert!(next >= 1.0);
    }

    #[test]
    fn no_change_when_ratio_in_band_at_min_elapsed() {
        // 3 shares in 30s = 6 SPM, target 6 SPM → ratio 1.0 → inside base band → no change
        assert!(vardiff_compute_next_diff(64.0, 3.0, 30.0, 6.0, false).is_none());
    }

    #[test]
    fn no_change_when_ratio_in_expanded_band() {
        // At elapsed=90s extra=0.10 → band [0.65, 1.35].
        // 3 shares in 30s at target 5 SPM → ratio = 12/5 = 2.4 → above 1.35 → triggers.
        // But ratio=0.70 (just inside expanded lower): 3 shares/30s=6 SPM, target≈8.57 → ratio≈0.70
        // Use a scenario clearly inside the expanded band: ratio=0.68 is below 0.65 lower (triggers).
        // Simpler: ratio=1.30 just inside [0.65,1.35] at elapsed=90s → None.
        // 3 shares in 30s = 6 SPM, target = 6/1.30 ≈ 4.615 SPM → ratio = 1.30
        let target = 6.0 / 1.30;
        assert!(vardiff_compute_next_diff(64.0, 3.0, 30.0, target, false).is_none());
    }

    #[test]
    fn below_min_elapsed_returns_none() {
        // 29s < VARDIFF_MIN_ELAPSED_SECS (30s) → no change regardless of ratio
        assert!(vardiff_compute_next_diff(64.0, 10.0, 29.0, 5.0, false).is_none());
    }

    #[test]
    fn below_min_shares_returns_none() {
        // Only 2 shares, need 3 (VARDIFF_MIN_SHARES) → no change
        assert!(vardiff_compute_next_diff(64.0, 2.0, 60.0, 5.0, false).is_none());
    }

    #[test]
    fn pow2_clamp_rounds_to_power_of_two() {
        // 0 shares, 95s > 60s no-share threshold → drop, result must be power of 2
        let next = vardiff_compute_next_diff(8.0, 0.0, 95.0, 10.0, true).expect("adjust");
        assert!(next.is_finite() && next >= 1.0);
        let log2 = next.log2();
        assert!(
            (log2 - log2.round()).abs() < 1e-9,
            "expected power of 2, got {}",
            next
        );
    }

    #[test]
    fn invalid_current_returns_none() {
        assert!(vardiff_compute_next_diff(0.0, 3.0, 60.0, 5.0, false).is_none());
        assert!(vardiff_compute_next_diff(f64::NAN, 3.0, 60.0, 5.0, false).is_none());
    }

    #[test]
    fn dead_band_expands_with_elapsed() {
        // At elapsed=30s (extra=0): band is [0.75, 1.25].
        // ratio=0.76 is just inside → no change.
        let target = 20.0;
        let shares_for_ratio_076 = 0.76 * target * (30.0 / 60.0); // ~7.6 shares in 30s
        // Need integer-ish shares; use ratio just inside the base band.
        // 3 shares in 30s = 6 SPM, target 7.89 → ratio ≈ 0.76 (just above 0.75 base lower)
        let t = 6.0 / 0.76;
        assert!(vardiff_compute_next_diff(64.0, 3.0, 30.0, t, false).is_none(),
            "ratio just inside base band at 30s should not adjust");

        // At elapsed=120s (extra=0.15): band is [0.60, 1.40].
        // Same ratio ~0.76 is now well inside the expanded band → still no change.
        assert!(vardiff_compute_next_diff(64.0, 3.0, 120.0, t, false).is_none(),
            "same ratio inside expanded band at 120s should not adjust");

        // ratio=0.58 is below the 120s lower bound (0.60) → should adjust.
        let t2 = 6.0 / 0.58;
        assert!(vardiff_compute_next_diff(64.0, 3.0, 120.0, t2, false).is_some(),
            "ratio below expanded lower bound at 120s should adjust");
    }

    // ── vardiff_forced_drop ──────────────────────────────────────────────────

    #[test]
    fn forced_drop_reduces_diff() {
        // Uses VARDIFF_FORCED_DROP_MULTIPLIER (0.25): 1024 * 0.25 = 256 — two pow2 steps down
        let next = vardiff_forced_drop(1024.0, false).expect("should drop");
        assert_eq!(next, 256.0);
    }

    #[test]
    fn forced_drop_pow2_clamp() {
        // Non-power-of-two: 100 * 0.25 = 25 → floor to nearest pow2 below = 16
        let next = vardiff_forced_drop(100.0, true).expect("should drop");
        assert!(next.is_finite() && next >= 1.0);
        let log2 = next.log2();
        assert!(
            (log2 - log2.round()).abs() < 1e-9,
            "expected power of 2, got {}",
            next
        );
        assert!(next < 100.0);
    }

    #[test]
    fn forced_drop_at_floor_returns_none() {
        // Already at minimum diff (1.0) — nothing to drop
        assert!(vardiff_forced_drop(1.0, false).is_none());
        assert!(vardiff_forced_drop(1.0, true).is_none());
    }

    #[test]
    fn forced_drop_invalid_input_returns_none() {
        assert!(vardiff_forced_drop(0.0, false).is_none());
        assert!(vardiff_forced_drop(-5.0, false).is_none());
        assert!(vardiff_forced_drop(f64::NAN, false).is_none());
    }
}
