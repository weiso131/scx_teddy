# Metrics

A metric is one measurement of how the workload is actually performing — game
FPS, frame time, input latency, whatever the workload exposes. It is what tells
the predictor whether an injected scheduling delay was acceptable to the user,
and it is the only thing that needs it.

The trait lives in `src/predictors/expt_tolerance/metric.rs`. Each implementation
lives in its own file under this directory.

## The `Metric` trait

```rust
pub trait Metric: Sized {
    fn measure() -> Result<Self>;
    fn compare(&self, other: &Self) -> Ordering;
}
```

- `measure` collects one sample and blocks until the workload produces new data.
  The FPS detector, for instance, waits on a futex that the Vulkan hook wakes
  once per second.
- `compare` returns `Greater` when `self` performed better, `Less` when worse,
  `Equal` when the two are indistinguishable. Each metric decides which
  direction is "better" — higher FPS is better, lower frame time is better — so
  a caller can always read `Less` as "this sample is worse".

What the struct holds between those two calls is entirely up to the
implementation.

## How the experiment loop uses it

```text
loop {
    let before  = M::measure()?;   // no injected delay
    // apply some scheduling delay
    let delayed = M::measure()?;   // with the delay
    // remove the delay
    let after   = M::measure()?;   // no injected delay again

    delayed.compare(&before);
    delayed.compare(&after);
    // worse than both -> that delay is probably not acceptable
}
```

The undelayed state is measured on **both** sides of the delayed one. Without
that, the workload's own fluctuation would be indistinguishable from an effect
of the delay. It does not remove the problem entirely — several rounds may be
needed before a verdict is trustworthy.

## `game_fps` — game FPS via a Vulkan layer

`game_fps.rs` is the reader side only. The measuring half is the Vulkan layer in
the **[`latency_creater`](https://github.com/weiso131/latency_creater) project,
under its `game_fps/` directory** — build and install that layer, or `measure()`
has nothing to talk to.

The layer intercepts `vkQueuePresentKHR` to time frames, and the two sides talk
over a POSIX shared-memory buffer (`/dev/shm/game_fps`, overridable with
`LATENCY_SHM_NAME`). The struct layout is defined in the layer's
`game_fps/fps_shm.h` and mirrored in `game_fps.rs`; **both sides must agree on
it**.

The handshake is reader-driven, which is what gives this side control over
*when* a window is measured:

1. The reader stores `request = 1`.
2. The layer sees it on its next present, accumulates one window, writes the
   fields, sets `request = 0` and `FUTEX_WAKE`s the reader.
3. The reader, parked in `FUTEX_WAIT`, wakes and reads the fields.

The layer will not write again until the reader re-arms, so the reader owns the
buffer while reading it — no seqlock needed. With no game running the layer
never clears `request`, so `measure()` just stays parked at ~0 CPU.

`compare` orders by FPS: higher is better, so `Less` means the sample rendered
worse.

## Writing your own metric

1. Add a file here, e.g. `src/predictors/expt_tolerance/metrics/mine.rs`, and
   implement `Metric`.
2. Register the module in `src/predictors/expt_tolerance/metrics.rs`:

   ```rust
   pub mod mine;
   ```

Pick the direction of `compare` so that `Less` means "performed worse". The
experiment loop relies on that being true for every metric.
