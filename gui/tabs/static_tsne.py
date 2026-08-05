"""Static t-SNE tab — loads a collected CSV, runs t-SNE, plots with plotly.

Optionally colours points by KMeans cluster from a model's `_result.json`,
or splits them into a target (tgid / ppid / tid) vs the rest.

A model JSON may also be supplied to pick the feature columns. A CSV carries
every collected column, but a model is trained on a subset (train.py's
META_COLUMNS and --exclude drop the rest), and the predictor only ever sees
that subset. Running t-SNE over all CSV columns therefore places points using
dimensions the predictor is blind to, so the picture does not explain the
clustering it sits next to. With a model selected we use its `features` list.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import scx_runner as runner
import theme


def render():
    st.title("Static t-SNE · plot a collected CSV")

    # --- CSV picker: /tmp dropdown OR a free-text path anywhere -------------
    csvs = runner.list_csvs()
    csv_names = [str(p) for p in csvs]
    # Default to the most recently produced CSV (may sit outside /tmp).
    default_csv = (str(runner.last_csv) if runner.last_csv is not None
                   else (csv_names[0] if csv_names else ""))
    c1, c2 = st.columns([1, 3])
    with c1:
        csv_custom = st.checkbox("Custom CSV path", value=False,
                                 key="static_csv_custom")
    with c2:
        if csv_custom:
            # Widget owns its value via key; seed once. Lets you point at a CSV
            # outside /tmp (e.g. one collected straight to an SSD path).
            st.session_state.setdefault("static_csv_text", default_csv)
            csv_path = st.text_input("CSV path", key="static_csv_text",
                                     label_visibility="collapsed")
        else:
            csv_path = st.selectbox(
                "CSV",
                options=csv_names if csv_names else [""],
                index=csv_names.index(default_csv) if default_csv in csv_names else 0,
                format_func=lambda s: s or "(no CSVs found — tick custom)",
                label_visibility="collapsed", key="static_csv_pick")

    # --- Cluster-result JSON picker (optional): dropdown OR free-text path ---
    results = runner.list_files("model_*_result.json")
    result_names = ["(none — single colour)"] + [str(p) for p in results]
    default_result = ""
    if runner.last_model is not None:
        rp = runner.result_path_for(runner.last_model)
        if rp.exists():
            default_result = str(rp)
    r1, r2 = st.columns([1, 3])
    with r1:
        result_custom = st.checkbox("Custom result path", value=False,
                                    key="static_result_custom")
    with r2:
        if result_custom:
            st.session_state.setdefault("static_result_text", default_result)
            result_choice = st.text_input(
                "Cluster result JSON path", key="static_result_text",
                label_visibility="collapsed")
        else:
            result_idx = (result_names.index(default_result)
                          if default_result in result_names else 0)
            result_choice = st.selectbox(
                "Cluster result JSON (optional)",
                options=result_names, index=result_idx,
                label_visibility="collapsed", key="static_result_pick")

    # --- Model picker (optional): selects which columns t-SNE may use --------
    models = [str(p) for p in runner.list_models()]
    if runner.last_model is not None and str(runner.last_model) not in models:
        models.insert(0, str(runner.last_model))
    model_names = ["(none — every CSV column)"] + models
    default_model = str(runner.last_model) if runner.last_model is not None else ""
    m1, m2 = st.columns([1, 3])
    with m1:
        model_custom = st.checkbox("Custom model path", value=False,
                                   key="static_model_custom")
    with m2:
        if model_custom:
            st.session_state.setdefault("static_model_text", default_model)
            model_choice = st.text_input(
                "Model JSON path", key="static_model_text",
                label_visibility="collapsed")
        else:
            model_idx = (model_names.index(default_model)
                         if default_model in model_names else 0)
            model_choice = st.selectbox(
                "Model JSON (optional — restricts features to the trained set)",
                options=model_names, index=model_idx,
                label_visibility="collapsed", key="static_model_pick")

    hl_text = st.text_input(
        "Highlight (field=ids, e.g. `tgid=1234,5678`)",
        placeholder="leave empty to colour by cluster")

    plot_clicked = st.button("▶ Plot t-SNE", type="primary")

    # A button is True only on the rerun that clicked it. The Overall tab's
    # 1 Hz st.rerun() fires reruns of the whole app, so if we gated the figure
    # on `plot_clicked` it would vanish one second later. Instead the click
    # *computes* and stashes the figure in session_state; the figure below is
    # drawn from that stash on every rerun, so it persists until recomputed.
    if not plot_clicked:
        if "static_fig" in st.session_state:
            fig, caption = st.session_state["static_fig"]
            st.plotly_chart(fig, width="stretch",
                            config={"displayModeBar": True})
            st.caption(caption)
        else:
            st.caption("Press the button — t-SNE is moderately CPU-bound on "
                       "large CSVs, so we don't recompute on every keystroke.")
        return

    if not csv_path or not Path(csv_path).exists():
        st.error(f"CSV not found: {csv_path}")
        return

    # Lazy imports — sklearn is heavy, don't pay on every Streamlit reload.
    from sklearn.manifold import TSNE
    from sklearn.preprocessing import StandardScaler

    # Which columns the model was trained on, if one was named. Read before the
    # spinner so a bad path fails loudly instead of silently plotting the wrong
    # space — a t-SNE over the wrong columns still looks like a valid picture.
    model_features: list[str] | None = None
    if model_choice and model_choice != model_names[0]:
        if not Path(model_choice).exists():
            st.error(f"Model not found: {model_choice}")
            return
        try:
            with open(model_choice) as f:
                model_features = list(json.load(f)["features"])
        except (OSError, ValueError, KeyError, TypeError) as e:
            st.error(f"Could not read `features` from {model_choice}: {e}")
            return

    with st.spinner("Loading & running t-SNE…"):
        df = pd.read_csv(csv_path)
        meta = {"tid", "tgid", "ppid", "ancestor", "comm"}
        if model_features is not None:
            missing = [c for c in model_features if c not in df.columns]
            if missing:
                st.error(
                    "CSV is missing columns this model was trained on: "
                    f"{', '.join(missing)}. The CSV and the model come from "
                    "different feature sets — recollect or retrain.")
                return
            feature_cols = model_features
        else:
            feature_cols = [c for c in df.columns if c not in meta]
        if not feature_cols:
            st.error("CSV has no feature columns.")
            return
        if len(df) < 3:
            st.error(f"Need ≥3 tasks for t-SNE (have {len(df)}).")
            return
        X = StandardScaler().fit_transform(df[feature_cols].values)
        n = X.shape[0]
        perplexity = max(2.0, min(30.0, (n - 1) / 3.0))
        coords = TSNE(n_components=2, perplexity=perplexity,
                      init="pca", random_state=42).fit_transform(X)
        df["x"] = coords[:, 0]
        df["y"] = coords[:, 1]

    # Decide colouring scheme. Highlight takes precedence over cluster.
    hl_field, hl_ids = "", None
    if hl_text.strip() and "=" in hl_text:
        f, ids = hl_text.split("=", 1)
        hl_field = f.strip()
        try:
            hl_ids = {int(x) for x in ids.split(",") if x.strip()}
        except ValueError:
            hl_ids = set()

    fig = go.Figure()
    if hl_ids is not None and hl_field in df.columns:
        tgt = df[df[hl_field].isin(hl_ids)]
        oth = df[~df[hl_field].isin(hl_ids)]
        fig.add_trace(go.Scatter(
            x=oth["x"], y=oth["y"], mode="markers", name="other",
            marker=dict(size=6, color="#555", opacity=0.5),
            hovertext=oth.get("comm", oth["tid"]),
            hovertemplate="%{hovertext}<extra></extra>"))
        fig.add_trace(go.Scatter(
            x=tgt["x"], y=tgt["y"], mode="markers", name="target",
            marker=dict(size=11, color="#ff5252",
                        line=dict(color="white", width=1)),
            hovertext=tgt.get("comm", tgt["tid"]),
            hovertemplate="%{hovertext}<extra></extra>"))
        title = f"target {hl_field} ∈ {sorted(hl_ids)}"
    elif result_choice != result_names[0] and Path(result_choice).exists():
        with open(result_choice) as f:
            clusters = json.load(f)
        tid_to_cluster: dict[int, int] = {}
        for k, members in clusters.items():
            idx = int(k.rsplit("_", 1)[-1])
            for m in members:
                tid_to_cluster[int(m["tid"])] = idx
        labels = df["tid"].map(tid_to_cluster).fillna(-1).astype(int)
        for c in sorted(labels.unique()):
            mask = labels == c
            name = "unlabelled" if c == -1 else f"cluster {c}"
            colour = "#666" if c == -1 else theme.cluster_color(c)
            fig.add_trace(go.Scatter(
                x=df.loc[mask, "x"], y=df.loc[mask, "y"],
                mode="markers", name=name,
                marker=dict(size=7, color=colour, opacity=0.85),
                hovertext=df.loc[mask].get("comm", df.loc[mask, "tid"]),
                hovertemplate="%{hovertext}<extra></extra>"))
        title = "coloured by KMeans cluster"
    else:
        fig.add_trace(go.Scatter(
            x=df["x"], y=df["y"], mode="markers", name="tasks",
            marker=dict(size=7, color="#1f77b4", opacity=0.85),
            hovertext=df.get("comm", df["tid"]),
            hovertemplate="%{hovertext}<extra></extra>"))
        title = "all tasks"

    fig.update_layout(
        template="plotly_dark", height=620,
        margin=dict(l=10, r=10, t=40, b=10),
        title=dict(text=f"t-SNE · {title}", x=0.5),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(title="dim 1", showgrid=False, zeroline=False),
        yaxis=dict(title="dim 2", showgrid=False, zeroline=False),
    )
    # Stash so the figure survives later reruns (e.g. the Overall tab's 1 Hz
    # refresh) instead of being recomputed or blanked.
    # Name the feature space in the caption: the same CSV plotted with and
    # without a model gives two different pictures, and only the model one
    # matches what the predictor clusters on.
    if model_features is not None:
        dropped = [c for c in df.columns if c not in meta
                   and c not in set(feature_cols) and c not in ("x", "y")]
        caption = (f"{len(df)} tasks · {len(feature_cols)} model features: "
                   f"{', '.join(feature_cols)}")
        if dropped:
            caption += f" · ignored CSV columns: {', '.join(dropped)}"
    else:
        caption = (f"{len(df)} tasks · {len(feature_cols)} CSV columns "
                   "(no model — may include features the predictor ignores)")
    st.session_state["static_fig"] = (fig, caption)
    st.plotly_chart(fig, width="stretch",
                    config={"displayModeBar": True})
    st.caption(caption)
