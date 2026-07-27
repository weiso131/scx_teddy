use anyhow::Result;

/// One measurement of how the workload is actually performing (game FPS, frame
/// time, input latency, ...). What a metric holds is up to the implementation;
/// the experiment loop only ever measures and scores. Used by the predictor
/// that searches for a task's tolerable scheduling delay — nothing else needs it.
///
/// The loop that finds a task's tolerable scheduling delay is, in outline:
///
/// ```text
/// loop {
///     let before = M::measure(secs)?;   // no injected delay
///     // apply some scheduling delay
///     let delayed = M::measure(secs)?;  // with the delay
///     // remove the delay
///     let after = M::measure(secs)?;    // no injected delay again
///
///     delayed.regression(&before, &after); // how much the delay cost
/// }
/// ```
///
/// Measuring the undelayed state on both sides is what keeps the workload's own
/// fluctuation from being read as an effect of the delay.
pub trait Metric: Sized {
    /// Collect one sample over a window `secs` seconds long, blocking until the
    /// workload has produced that much data. The caller sets the window because
    /// only it knows how long the effect it is looking for takes to show up: a
    /// cluster whose tasks wake rarely needs a longer window before the injected
    /// delay is visible at all. Implementations may reject `secs == 0`.
    fn measure(secs: u32) -> Result<Self>;

    /// How much worse this delayed sample is than the undelayed ones around it,
    /// as a percentage. 0 means indistinguishable, 50 means it performed half as
    /// well, negative means it came out ahead.
    fn regression(&self, before: &Self, after: &Self) -> f64;
}
