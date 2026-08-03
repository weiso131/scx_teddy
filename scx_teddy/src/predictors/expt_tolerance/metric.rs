use anyhow::Result;
use std::fmt::Display;
use std::ops::AddAssign;

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
    /// One round's regression, and the running total of them. A metric that
    /// watches several signals keeps them apart in here rather than flattening
    /// them into one number, so [`Metric::is_bad`] can judge each on its own
    /// scale. `Default` is the empty total the loop starts from, `AddAssign`
    /// accumulates a round into it, and `Display` renders it for the log.
    ///
    /// The experiment loop never inspects the value — accumulating and judging
    /// it are the only things it does with one.
    type Drop: Default + AddAssign + Display;

    /// Collect one sample over a window `secs` seconds long, blocking until the
    /// workload has produced that much data. The caller sets the window because
    /// only it knows how long the effect it is looking for takes to show up: a
    /// cluster whose tasks wake rarely needs a longer window before the injected
    /// delay is visible at all. Implementations may reject `secs == 0`.
    fn measure(secs: u32) -> Result<Self>;

    /// How much worse this delayed sample is than the undelayed ones around it.
    /// Zero means indistinguishable and negative means it came out ahead, so
    /// that summing rounds lets noise cancel instead of only ever accumulating.
    fn regression(&self, before: &Self, after: &Self) -> Self::Drop;

    /// Whether a total accumulated over the experiment's rounds is bad enough to
    /// end the search for this cluster. The threshold belongs to the metric: it
    /// is the only thing that knows what its signals are measured in.
    fn is_bad(total: &Self::Drop) -> bool;
}
