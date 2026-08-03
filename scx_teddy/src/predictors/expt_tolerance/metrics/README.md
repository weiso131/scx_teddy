# Metrics

A metric is one measurement of how the workload is actually performing — game
FPS, audio throughput, input latency, whatever the workload exposes. It is what
tells the predictor whether an injected scheduling delay was acceptable to the
user, and it is the only thing that needs it.

The trait lives in `src/predictors/expt_tolerance/metric.rs`. Each implementation
lives in its own file under this directory.

## The `Metric` trait

```rust
pub trait Metric: Sized {
    type Drop: Default + AddAssign + Display;

    fn measure(secs: u32) -> Result<Self>;
    fn regression(&self, before: &Self, after: &Self) -> Self::Drop;
    fn is_bad(total: &Self::Drop) -> bool;
}
```

- `measure` collects one sample over a `secs`-second window and blocks until the
  workload has produced that much data. The caller picks the window because only
  it knows how long the effect it is looking for takes to show up — a cluster
  whose tasks wake rarely needs a longer one before an injected delay is visible
  at all. Implementations may reject `secs == 0`.
- `regression` scores how much worse the delayed sample is than the undelayed
  ones around it. Zero means indistinguishable and negative means it came out
  ahead, so summing rounds lets noise cancel rather than only ever accumulating.
- `is_bad` judges a total accumulated over the experiment's rounds. The
  threshold belongs to the metric: it is the only thing that knows what its
  signals are measured in.

`Drop` is the metric's own type, so a metric watching several signals keeps them
apart instead of flattening them into one number — the experiment loop never
inspects one, it only accumulates, judges and prints it. What the sample struct
holds between `measure` and `regression` is likewise up to the implementation.

## How the experiment loop uses it

```text
let mut total = M::Drop::default();
for _ in 0..EXPT_ROUNDS {
    let before  = M::measure(secs)?;   // no injected delay
    // apply some scheduling delay
    let delayed = M::measure(secs)?;   // with the delay
    // remove the delay
    let after   = M::measure(secs)?;   // no injected delay again

    total += delayed.regression(&before, &after);
}
if M::is_bad(&total) { /* that delay is not acceptable */ }
```

The undelayed state is measured on **both** sides of the delayed one. Without
that, the workload's own fluctuation would be indistinguishable from an effect
of the delay. It does not remove the problem entirely, which is why the verdict
is taken over several rounds rather than one.

## `game_latency` — what the game itself can feel

`game_latency.rs` scores two signals over one shared window:

| signal | source | measures |
|---|---|---|
| framerate | Vulkan layer over POSIX shm | rendering keeping up |
| audio rate | `pa_stream_write` uprobe over a BPF map | audio pipeline being fed |

`is_bad` fires when **either** exceeds its own threshold: stuttering video and
broken audio are each a failure on their own, and scoring them apart keeps one
from being averaged away by the other holding up.

### Video

This file is the reader side only. The measuring half is the Vulkan layer in the
**[`latency_creater`](https://github.com/weiso131/latency_creater) project, under
its `game_fps/` directory** — build and install that layer, or `measure()` has
nothing to talk to.

The layer intercepts `vkQueuePresentKHR` to time frames, and the two sides talk
over a POSIX shared-memory buffer (`/dev/shm/game_fps`, overridable with
`LATENCY_SHM_NAME`). The struct layout is defined in the layer's
`game_fps/fps_shm.h` and mirrored here; **both sides must agree on it**.

The handshake is reader-driven, which is what gives this side control over *when*
a window is measured and *how long* it is. `request_sec` carries both the request
and its parameter, so `0` cannot be a window length — it already means idle:

1. The reader stores `request_sec = N` (the window length in seconds).
2. The layer sees the nonzero value on its next present, accumulates a window
   `N` seconds long, writes the fields, sets `request_sec = 0` and `FUTEX_WAKE`s
   the reader.
3. The reader, parked in `FUTEX_WAIT`, wakes and reads the fields.

The layer will not write again until the reader re-arms, so the reader owns the
buffer while reading it — no seqlock needed. With no game running the layer never
clears `request_sec`, so `measure()` just stays parked at ~0 CPU.

### Audio

The BPF probe on `pa_stream_write` counts calls while a window is open; the
handshake is `audio_expt_t` in `intf.h`. There is no futex here — a BPF program
cannot `FUTEX_WAKE` — so the close is acknowledged through a three-state flag
and userspace polls for it:

1. Userspace stores `RUN` and zeroes the count, opening the window.
2. The probe increments the count on every call while it sees `RUN`.
3. Userspace stores `STOP` to close it.
4. The probe sees `STOP` on its next call and answers `IDLE`, which is what makes
   the count settled — the probe cannot be mid-increment at that point.

The probe may never run again (a silent or paused game, or an audio thread
starved by the very delay under test), so step 4 has a timeout: userspace takes
the count as it stands and reclaims the window itself. The count is still every
write of the window, only its end boundary is as old as the last call.

The **video side times the window**: audio is armed before blocking on the layer
and closed once the layer answers, so both describe the same stretch of time
without a second clock. That makes the audio window as long as the layer took
rather than exactly `secs`, so the rate is divided by the measured elapsed time.

With no audio at all the rate is 0 in every window, its drop is 0, and the metric
degrades to the framerate alone — no switch to flip.

## Writing your own metric

1. Add a file here, e.g. `src/predictors/expt_tolerance/metrics/mine.rs`, and
   implement `Metric`.
2. Register the module in `src/predictors/expt_tolerance/metrics.rs`:

   ```rust
   pub mod mine;
   ```

Keep `regression` signed so that a sample which came out ahead scores negative;
the experiment loop relies on that to let round-to-round noise cancel.
