"""Shared model-picker + scheduling-config editor.

Both the Classify tab (default model + config) and the specialization-target
panel (`_target.py`, the target family's own model + config) need the exact
same thing: pick a trained model JSON, then edit a per-cluster scheduling table
(prio / slice_ns / cpu_kind / cpu_prefer) sized to that model's cluster count.
This module is that widget, factored out so the two callers can't drift.

`render_model_and_config(key_prefix, ...)` returns `(model_path, edited_df)`:
the chosen model path (str, possibly empty) and the edited table (a DataFrame,
or None when no readable model is selected so the table can't be sized). The
caller serializes the df with `df_to_config` + `runner.write_config` at the
point it actually needs a file.

Streamlit note: every widget key is prefixed with `key_prefix`, and we never
write back into a widget's own key (that clobbers in-progress edits — the
"hesitate and you lose" anti-pattern). Callers must pass distinct prefixes.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

import scx_runner as runner
import sys_topology


def _model_choices() -> list[str]:
    """Trained models reachable this session: the /tmp data dir plus the most
    recent one (which may live on an SSD custom dir, outside /tmp)."""
    models = [str(p) for p in runner.list_models()]
    if runner.last_model is not None and str(runner.last_model) not in models:
        models.insert(0, str(runner.last_model))
    return models


def _cpu_kind_label(k: int, groups: list) -> str:
    """A cpu_kind value rendered as `"<int> · <meaning>"`. 0 = any CPU; 1-based
    into the fast→slow groups, so kind k names groups[k-1] (P-core / E-core /
    tier-N). The int is the leading token, which makes the label trivially
    reversible (see _cpu_kind_int) without threading the group list everywhere."""
    if k == 0:
        return "0 · any"
    if 1 <= k <= len(groups):
        return f"{k} · {groups[k - 1].name}"
    return f"{k} · kind {k}"


def _cpu_kind_int(label: str) -> int:
    """Inverse of _cpu_kind_label: the int is the leading token before ` · `."""
    try:
        return int(str(label).split("·", 1)[0].strip())
    except (ValueError, IndexError):
        return runner.CONFIG_DEFAULT_CPU_KIND


def _cpu_kind_options(groups: list) -> list[str]:
    """All valid cpu_kind labels for this machine: 0 (any) plus one per kind."""
    return [_cpu_kind_label(k, groups) for k in range(len(groups) + 1)]


def _row_from_entry(cluster: str, entry: dict | None, groups: list) -> dict:
    """One editor row. `entry` is a cluster's config dict (from a loaded file)
    or None to fall back to the GUI defaults. Only the fields the editor shows
    are pulled out; extra keys are dropped, so re-serializing always writes a
    clean entry.

    cpu_kind and cpu_prefer are held as labelled strings (so the table shows
    dropdowns) and mapped back to ints on save."""
    entry = entry or {}
    prefer_int = entry.get("cpu_prefer", runner.CONFIG_DEFAULT_CPU_PREFER)
    kind_int = entry.get("cpu_kind", runner.CONFIG_DEFAULT_CPU_KIND)
    return {
        "cluster": cluster,
        "prio": entry.get("prio", runner.CONFIG_DEFAULT_PRIO),
        "slice_ns": entry.get("slice_ns", runner.CONFIG_DEFAULT_SLICE_NS),
        "cpu_kind": _cpu_kind_label(int(kind_int), groups),
        "cpu_prefer": runner.CPU_PREFER_LABELS.get(
            int(prefer_int), runner.CPU_PREFER_LABELS[0]),
    }


def _seed_editor_df(n_clusters: int, groups: list,
                    loaded: tuple[dict, dict] | None = None) -> pd.DataFrame:
    """One row per cluster id (0..n-1) plus a final `default` row. The column
    set is the row label + the editable knobs. `groups` is the discovered CPU
    topology, used to label the cpu_kind dropdown.

    `loaded` = (clusters, default) parsed from an existing config file. The
    table is always sized to `n_clusters` (the model's cluster count): a loaded
    cluster id beyond that is dropped, a missing one is filled with defaults.
    `loaded=None` seeds every row with the GUI defaults (the "Edit in GUI"
    fresh-start case)."""
    loaded_clusters, loaded_default = (loaded if loaded is not None else ({}, {}))
    rows = [_row_from_entry(str(i), loaded_clusters.get(str(i)), groups)
            for i in range(n_clusters)]
    rows.append(_row_from_entry("default", loaded_default, groups))
    return pd.DataFrame(rows)


def df_to_config(df: pd.DataFrame) -> tuple[dict, dict]:
    """Split the editor table back into ({clusters}, default) scx_teddy reads.
    The `default` row becomes the top-level default; every other row is a
    numbered cluster entry."""
    clusters: dict[str, dict] = {}
    default = runner.make_cluster_entry()
    for _, r in df.iterrows():
        # cpu_kind and cpu_prefer are held as labels in the table; map back.
        prefer = runner.CPU_PREFER_BY_LABEL.get(
            str(r["cpu_prefer"]), runner.CONFIG_DEFAULT_CPU_PREFER)
        entry = runner.make_cluster_entry(
            prio=r["prio"], slice_ns=r["slice_ns"],
            cpu_kind=_cpu_kind_int(r["cpu_kind"]),
            cpu_prefer=prefer)
        if str(r["cluster"]).strip().lower() == "default":
            default = entry
        else:
            clusters[str(r["cluster"]).strip()] = entry
    return clusters, default


def _render_model_picker(key_prefix: str, label: str) -> str:
    """Dropdown of known models + free-text override. Returns the chosen path
    (possibly empty). Mirrors the Classify default-model picker.

    The widgets own their value purely via their `key` — we seed once with
    `setdefault` and never pass `index=`/`value=` again. Passing `index=` on
    every rerun is what silently reset the selection: a background rerun (the
    scanner/log nudger) recomputed `index` from a shifting model list and
    Streamlit reapplied it, clobbering the user's pick. Seed-once + key-only is
    stable across reruns."""
    models = _model_choices()
    default_model = (str(runner.last_model) if runner.last_model is not None
                     else (models[0] if models else ""))
    c1, c2 = st.columns([1, 3])
    with c1:
        st.session_state.setdefault(f"{key_prefix}_model_custom", not models)
        model_custom = st.checkbox("Custom path", key=f"{key_prefix}_model_custom")
    with c2:
        st.caption(label)
        if model_custom:
            st.session_state.setdefault(f"{key_prefix}_model_text", default_model)
            return st.text_input("Model JSON path", key=f"{key_prefix}_model_text",
                                 label_visibility="collapsed")
        opts = models if models else [""]
        # Seed the selection once; afterwards the key holds it. Guard against a
        # seeded value that's no longer in the list (model deleted) by falling
        # back to the first option, else Streamlit raises.
        sel_key = f"{key_prefix}_model_select"
        if (st.session_state.get(sel_key) not in opts):
            st.session_state[sel_key] = default_model if default_model in opts else opts[0]
        return st.selectbox(
            "Model JSON", options=opts,
            format_func=lambda s: s or "(no models found — tick custom)",
            key=sel_key, label_visibility="collapsed")


def render_model_and_config(
    key_prefix: str,
    *,
    model_label: str = "Model JSON",
    with_save: bool = False,
    default_config_path: Path | None = None,
) -> tuple[str, pd.DataFrame | None]:
    """Render a model picker + a scheduling-config table sized to that model.

    Returns `(model_str, edited_df)`. `edited_df` is None when no readable model
    is picked (the table can't be sized) — callers must handle that. The table
    is the source of truth; serialize it with `df_to_config` when needed.

    `with_save=True` adds a guarded "Save back to file" button for the
    "Existing file" source (Classify uses it; the target panel doesn't need it).
    `default_config_path` seeds the "Existing file" Custom-path box.
    """
    model_str = _render_model_picker(key_prefix, model_label)

    # Config source: "Edit in GUI" starts from defaults; "Existing file" loads
    # a config off disk to seed the table. Either way the table is the source of
    # truth and gets re-serialized to a fresh /tmp config by the caller on use.
    st.markdown("##### Scheduling config")
    config_mode = st.radio(
        "Config source", ["Edit in GUI", "Existing file"], index=0,
        horizontal=True, label_visibility="collapsed",
        key=f"{key_prefix}_config_mode")

    src_path = ""
    if config_mode == "Existing file":
        # Dropdown of known configs (tmpfs config_*.json + repo-root config/),
        # with a Custom-path escape hatch for anything elsewhere. Mirrors the
        # model picker; seed-once + key-only so a background rerun can't reset it.
        configs = [str(p) for p in runner.list_configs()]
        cfg_custom_key = f"{key_prefix}_config_custom"
        st.session_state.setdefault(cfg_custom_key, not configs)
        cfg_custom = st.checkbox("Custom path", key=cfg_custom_key)
        if cfg_custom:
            seed = str(default_config_path or (runner.CONFIG_DIR / "config.json"))
            st.session_state.setdefault(f"{key_prefix}_config_path", seed)
            src_path = st.text_input("Scheduling config JSON path to load & edit",
                                     key=f"{key_prefix}_config_path")
        elif configs:
            sel_key = f"{key_prefix}_config_select"
            if st.session_state.get(sel_key) not in configs:
                st.session_state[sel_key] = configs[0]
            src_path = st.selectbox(
                "Scheduling config JSON to load & edit", options=configs,
                key=sel_key, label_visibility="collapsed")
        else:
            st.caption("No saved configs found — tick Custom path to type one.")

    # The table needs the model's cluster count. Without a readable model we
    # can't size it, so it vanishes (the caller's Start/Apply still renders).
    n = runner.model_n_clusters(Path(model_str)) if model_str else None
    if n is None:
        st.info("Pick a readable model JSON above — the config table is "
                "sized from its cluster count.")
        return model_str, None

    loaded = None
    if config_mode == "Existing file":
        if src_path and Path(src_path).exists():
            loaded = runner.read_config(Path(src_path))
            if loaded is None:
                st.warning(f"Couldn't parse `{src_path}` — seeding with "
                           "defaults instead.")
        elif src_path:
            st.warning(f"`{src_path}` not found — seeding with defaults.")

    cap = f"Model reports **{n}** clusters → {n} cluster rows + a default row."
    if loaded is not None:
        cap += " Loaded values shown; missing clusters use defaults."
    st.caption(cap)

    # CPU topology drives the cpu_kind dropdown labels (0 = any, then one entry
    # per kind named P-core / E-core / tier-N). Self-contained, like Overall.
    groups = sys_topology.discover()

    # Reseed only when the source signature changes (mode + file + n); otherwise
    # keep the user's in-table edits across reruns.
    df_key = f"{key_prefix}_cfg_df"
    sig = (config_mode, src_path, n)
    if st.session_state.get(f"{key_prefix}_cfg_sig") != sig:
        st.session_state[df_key] = _seed_editor_df(n, groups, loaded)
        st.session_state[f"{key_prefix}_cfg_sig"] = sig

    edited_df = st.data_editor(
        st.session_state[df_key],
        key=f"{key_prefix}_cfg_editor", hide_index=True,
        width="stretch", disabled=["cluster"],
        column_config={
            "cluster": st.column_config.TextColumn(
                "cluster", help="Cluster id from the model, or `default`."),
            "prio": st.column_config.NumberColumn(
                "prio", help="0 = highest, 11 = lowest.", min_value=0,
                max_value=11, step=1),
            "slice_ns": st.column_config.NumberColumn(
                "slice_ns", help="Fixed time slice in ns (floored at "
                "100000 — the real minimum the scheduler grants).",
                min_value=runner.CONFIG_DEFAULT_SLICE_NS, step=1000),
            "cpu_kind": st.column_config.SelectboxColumn(
                "cpu_kind", help="Which CPU kind to pin to. '0 · any' = "
                "shared DSQ (any CPU); otherwise 1-based, 1 = fastest tier.",
                options=_cpu_kind_options(groups), required=True),
            "cpu_prefer": st.column_config.SelectboxColumn(
                "cpu_prefer", help="select_cpu speed preference. "
                "'no preference' lets the scheduler auto-derive it from "
                "cpu_kind; 'prefer fast' / 'prefer slow' force it.",
                options=list(runner.CPU_PREFER_LABELS.values()),
                required=True),
        })
    st.session_state[df_key] = edited_df

    # Save edits back to the loaded file — "Existing file" mode only, guarded by
    # a confirm box. Start/Apply always uses a fresh /tmp copy, so writing the
    # original is never automatic: the user opts in here (don't clobber a config
    # by accident).
    if with_save and config_mode == "Existing file" and src_path:
        confirm = st.checkbox(f"Confirm overwrite of `{src_path}`",
                              key=f"{key_prefix}_save_confirm")
        if st.button("💾 Save back to file", disabled=not confirm,
                     key=f"{key_prefix}_save"):
            try:
                clusters, default = df_to_config(edited_df)
                runner.save_config_to(Path(src_path), clusters, default)
                st.toast(f"Saved → {src_path}")
            except OSError as e:
                st.error(f"Save failed: {e}")

    return model_str, edited_df
