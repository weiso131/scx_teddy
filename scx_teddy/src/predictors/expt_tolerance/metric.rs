use anyhow::Result;
use std::cmp::Ordering;

/// One measurement of how the workload is actually performing (game FPS, frame
/// time, input latency, ...). What a metric holds is up to the implementation;
/// the experiment loop only ever measures and compares. Used by the predictor
/// that searches for a task's tolerable scheduling delay — nothing else needs it.
///
/// The loop that finds a task's tolerable scheduling delay is, in outline:
///
/// ```text
/// loop {
///     let before = M::measure()?;      // no injected delay
///     // apply some scheduling delay
///     let delayed = M::measure()?;     // with the delay
///     // remove the delay
///     let after = M::measure()?;       // no injected delay again
///
///     delayed.compare(&before);
///     delayed.compare(&after);
///     // worse than both -> that delay is probably not acceptable
/// }
/// ```
///
/// Measuring the undelayed state on both sides is what keeps the workload's own
/// fluctuation from being read as an effect of the delay.
pub trait Metric: Sized {
    /// Collect one sample. Blocks until the workload produces new data (the FPS
    /// detector, for instance, waits on a futex the hook wakes once per second).
    fn measure() -> Result<Self>;

    /// How this sample compares to another. `Greater` means `self` performed
    /// better, `Less` means worse, `Equal` means the two are indistinguishable.
    /// Each metric defines which direction is "better" (higher FPS is better,
    /// lower frame time is better), so callers can always read `Less` as worse.
    fn compare(&self, other: &Self) -> Ordering;
}
