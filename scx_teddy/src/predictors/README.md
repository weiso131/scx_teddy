# Predictors

A predictor maps a task's `TaskStats` to a cluster/class index. The scheduler
uses that index to look up scheduling parameters (prio, slice, cpu_kind, ...).

The trait and the model loader live in `src/predictor.rs`. Each concrete
implementation lives in its own file under this directory.

## The `Predictor` trait

```rust
pub trait Predictor: Send + Sync {
    fn predict(&self, stats: &mut TaskStats) -> Option<usize>;
    fn n_outputs(&self) -> usize;
}
```

- `predict` receives `&mut TaskStats` and returns the chosen index, or `None`
  when there is nothing to do this cycle.
- `n_outputs` reports how many distinct indices `predict` can return.

## Writing your own predictor

1. Add a file here, e.g. `src/predictors/mine.rs`, and implement `Predictor`
   for your type.
2. Register the module in `src/predictors.rs`:

   ```rust
   pub mod mine;
   ```

3. Add a match arm in `load_predictor` (`src/predictor.rs`) keyed on the
   model JSON's `"algorithm"` field.

Which features a predictor reads is entirely up to it. It gets the whole
`TaskStats`, so it picks whatever it needs. See `kmeans.rs` for a full
example, including how it collects named features from `TaskStats`.

## The `need_update` flag (read this)

`TaskStats::need_update` is set to `1` by `TaskStats` itself whenever new
events arrive. It is **never cleared by `TaskStats`** — clearing it is the
predictor's job.

The classify loop calls `predict` on every task every cycle. It does **not**
gate on `need_update`, so your `predict` is responsible for deciding whether a
task actually needs re-predicting:

- If you want to skip unchanged tasks, check `stats.need_update` at the top and
  return `None` when it is `0`; set it to `0` before doing the work so the next
  cycle skips this task until new events arrive.
- If you always want to predict, ignore the flag entirely.

`kmeans.rs` takes the first approach.

## Available stats

The raw fields and derived metrics a predictor can read are all in
`src/task_stats.rs`. The code is the reference — read it directly.
