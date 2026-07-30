#!/usr/bin/env python3
"""Train a KMeans model from event.csv and export to JSON for Rust consumption."""

import argparse
import json
import sys

import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

# Columns that are metadata, not features for training
META_COLUMNS = {"tid", "tgid", "ppid", "comm", "ancestor"}


def get_feature_columns(df, exclude=None):
    """Derive feature columns from the DataFrame (all columns except metadata).

    `exclude` drops further columns without re-collecting the CSV, which is how
    a feature the diagnostics flagged as degenerate or redundant gets tested
    against a model trained without it.
    """
    reserved = META_COLUMNS | {"label"} | set(exclude or ())
    return [col for col in df.columns if col not in reserved]


def load_train_config(path: str) -> list[str]:
    """Load comm prefixes from a train_config.config file.

    Returns a list of prefix strings. Lines starting with '#' and blank lines
    are ignored.
    """
    patterns = []
    with open(path) as f:
        for line in f:
            s = line.split("#")[0].strip()
            if s:
                patterns.append(s)
    return patterns


def select_by_patterns(df: "pd.DataFrame", patterns: list[str]) -> "pd.DataFrame":
    """Keep only rows whose comm matches any pattern (prefix match)."""
    if "comm" not in df.columns:
        print("Error: CSV does not contain 'comm' column.", file=sys.stderr)
        sys.exit(1)
    mask = df["comm"].astype(str).apply(
        lambda c: any(c == p or c.startswith(p) for p in patterns)
    )
    out = df[mask].copy()
    print(f"Selected {len(out)} tasks matching train_config patterns")
    return out


def find_best_k(X_scaled, k_range=range(2, 11)):
    """Use the elbow method (largest inertia drop) to pick K."""
    inertias = []
    for k in k_range:
        model = KMeans(n_clusters=k, n_init=10, random_state=42)
        model.fit(X_scaled)
        inertias.append(model.inertia_)
        print(f"  K={k}: inertia={model.inertia_:.2f}")

    # Find the K with the largest second derivative (elbow point)
    diffs = [inertias[i] - inertias[i + 1] for i in range(len(inertias) - 1)]
    diffs2 = [diffs[i] - diffs[i + 1] for i in range(len(diffs) - 1)]
    best_idx = np.argmax(diffs2) + 2  # +2 because diffs2 starts at k_range[2]
    best_k = list(k_range)[best_idx]
    return best_k, inertias


# A feature this concentrated on one value cannot separate anything; the few
# rows that differ just get scaled into outliers that claim a cluster of their own.
DEGENERATE_FRACTION = 0.95
# Rank correlation above this means two features are largely restating each
# other, and the pair gets double weight in the distance K-means minimizes.
REDUNDANT_RHO = 0.9
# Share of variance the PCA summary reports the dimensionality for.
PCA_VARIANCE_TARGET = 0.95


def report_feature_health(df, feature_columns):
    """Flag features that cannot contribute: near-constant, or binary.

    Rank correlation and PCA below both assume a feature has a distribution to
    speak of, so the degenerate ones are worth naming before reading those.
    """
    print(f"\n{'='*60}")
    print("Feature health")
    print(f"{'='*60}")
    print(f"{'feature':<24}{'distinct':>9}{'top value':>12}{'share':>8}  note")

    for col in feature_columns:
        counts = df[col].value_counts(normalize=True)
        top_val, top_share = counts.index[0], counts.iloc[0]
        distinct = df[col].nunique()

        if top_share >= DEGENERATE_FRACTION:
            note = f"near-constant (>={DEGENERATE_FRACTION:.0%} identical)"
        elif distinct == 2:
            note = "binary: a hard split, not a gradient"
        else:
            note = ""
        print(f"{col:<24}{distinct:>9}{top_val:>12.4g}{top_share:>8.1%}  {note}")


def report_redundancy(df, feature_columns):
    """Rank correlation between features, and the redundant pairs it exposes.

    Spearman rather than Pearson: these features are heavy-tailed enough that a
    monotone pair can still show a weak linear correlation, which reads as
    independence when it is not.
    """
    print(f"\n{'='*60}")
    print("Feature redundancy (Spearman rank correlation)")
    print(f"{'='*60}")

    rho = pd.DataFrame(
        spearmanr(df[feature_columns].values).statistic,
        index=feature_columns,
        columns=feature_columns,
    )
    print(rho.round(2).to_string())

    pairs = [
        (feature_columns[i], feature_columns[j], rho.iloc[i, j])
        for i in range(len(feature_columns))
        for j in range(i + 1, len(feature_columns))
        if abs(rho.iloc[i, j]) >= REDUNDANT_RHO
    ]
    print(f"\nPairs at |rho| >= {REDUNDANT_RHO}:")
    if not pairs:
        print("  none")
    for a, b, r in sorted(pairs, key=lambda p: -abs(p[2])):
        print(f"  {a:<24}{b:<24}{r:+.2f}  (one of the two is close to spare)")


def report_dimensionality(X_scaled, feature_columns):
    """How many independent directions the features actually span.

    Fewer components than features means the extra columns are not extra
    information — they are the same axis counted more than once.
    """
    print(f"\n{'='*60}")
    print("Effective dimensionality (PCA)")
    print(f"{'='*60}")

    pca = PCA().fit(X_scaled)
    cumulative = np.cumsum(pca.explained_variance_ratio_)
    n_needed = int(np.searchsorted(cumulative, PCA_VARIANCE_TARGET) + 1)
    for i, (ratio, cum) in enumerate(zip(pca.explained_variance_ratio_, cumulative), 1):
        print(f"  PC{i}: {ratio:6.1%}  cumulative {cum:6.1%}")
    print(
        f"\n{n_needed} of {len(feature_columns)} components carry "
        f"{PCA_VARIANCE_TARGET:.0%} of the variance"
    )

    # Loadings say which features move together; a shared sign and magnitude on
    # a dominant component is the same redundancy the pair list reports, seen
    # across more than two features at once.
    print("\nLoadings on the first three components:")
    loadings = pd.DataFrame(
        pca.components_[:3].T,
        index=feature_columns,
        columns=["PC1", "PC2", "PC3"],
    )
    print(loadings.round(2).to_string())


def report_cluster_quality(X_scaled, labels, n_clusters, k_range=range(2, 13)):
    """Silhouette at the chosen K, against what other K values would score.

    A K whose score barely stands out from its neighbours means the data has no
    natural grouping at that scale and the boundaries are somewhat arbitrary.
    """
    print(f"\n{'='*60}")
    print("Cluster quality (silhouette)")
    print(f"{'='*60}")

    if len(set(labels)) < 2:
        print("Only one cluster was populated; silhouette is undefined.")
        return

    print(f"K={n_clusters} (selected): {silhouette_score(X_scaled, labels):.3f}")
    print("\nFor comparison:")
    scores = {}
    for k in k_range:
        if k >= len(X_scaled):
            break
        km = KMeans(n_clusters=k, n_init=10, random_state=42).fit(X_scaled)
        scores[k] = silhouette_score(X_scaled, km.labels_)
        mark = " <- selected" if k == n_clusters else ""
        print(f"  K={k:2d}: {scores[k]:.3f}{mark}")

    best_k = max(scores, key=scores.get)
    spread = max(scores.values()) - min(scores.values())
    print(f"\nBest by silhouette: K={best_k} ({scores[best_k]:.3f})")
    if spread < 0.15:
        print(
            f"Scores span only {spread:.3f} across the range — no K stands out, "
            "so the data has no strong natural grouping."
        )


def report_cluster_sizes(df, feature_columns, labels, n_clusters):
    """Cluster sizes, and for the small ones, what set them apart.

    A cluster of one is a normal outcome — a task can simply be the only one of
    its kind. What the feature it stands out on tells you is whether that is the
    case: separated on a feature with a real distribution, it is a genuine
    category of one; separated on a near-constant feature, the split says only
    that it is the rare task with a nonzero value there.
    """
    print(f"\n{'='*60}")
    print("Cluster sizes")
    print(f"{'='*60}")

    sizes = np.bincount(labels, minlength=n_clusters)
    degenerate = {
        col
        for col in feature_columns
        if df[col].value_counts(normalize=True).iloc[0] >= DEGENERATE_FRACTION
    }

    for c, size in enumerate(sizes):
        print(f"  cluster {c}: {size:4d} tasks")
        if size > 2 or size == 0:
            continue
        # Which feature this cluster sits furthest from the rest on: the axis
        # the split was actually bought with.
        members = df.loc[labels == c, feature_columns]
        others = df.loc[labels != c, feature_columns]
        gaps = {
            col: abs(members[col].median() - others[col].median()) / spread
            for col in feature_columns
            if (spread := df[col].std()) > 0
        }
        if not gaps:
            continue
        for col in sorted(gaps, key=gaps.get, reverse=True)[:2]:
            flag = "  (near-constant feature)" if col in degenerate else ""
            print(f"      set apart by {col}: {gaps[col]:.1f} sd from the rest{flag}")


def report_comm_spread(df, labels, n_clusters):
    """How far the split departs from what the command name alone would give.

    Threads sharing a name being placed apart is the point of classifying on
    behaviour: if clusters and names agreed, the features would be an expensive
    way to read `comm`. This measures that departure rather than warning about
    it — it is only worth a second look if it is near zero.
    """
    if "comm" not in df.columns:
        return

    print(f"\n{'='*60}")
    print("Departure from name-based grouping")
    print(f"{'='*60}")

    comm = df["comm"].astype(str).values
    by_comm = pd.crosstab(comm, labels)

    split = by_comm[(by_comm > 0).sum(axis=1) > 1]
    n_repeated = int((by_comm.sum(axis=1) > 1).sum())
    print(
        f"{len(split)} of {n_repeated} commands with more than one task were "
        "split across clusters:"
    )
    if split.empty:
        print("  none — the clustering reproduces the command names")
    for name, row in split.iterrows():
        where = ", ".join(f"c{c}x{n}" for c, n in row[row > 0].items())
        print(f"  {name:<24}{int(row.sum()):>4} tasks over "
              f"{int((row > 0).sum())} clusters: {where}")

    print("\nDistinct commands per cluster:")
    for c in range(n_clusters):
        names = sorted(set(comm[labels == c]))
        shown = ", ".join(names[:5]) + (", ..." if len(names) > 5 else "")
        print(f"  cluster {c}: {len(names):3d} distinct  {shown}")


def report_features(df, feature_columns, X_scaled, labels, n_clusters):
    """Print the feature/clustering diagnostics after the classification dump.

    These say whether the features can support the split at all; they say
    nothing about whether the clusters group tasks that want the same treatment,
    which needs a measured outcome the CSV does not carry.
    """
    report_feature_health(df, feature_columns)
    report_redundancy(df, feature_columns)
    report_dimensionality(X_scaled, feature_columns)
    report_cluster_quality(X_scaled, labels, n_clusters)
    report_cluster_sizes(df, feature_columns, labels, n_clusters)
    report_comm_spread(df, labels, n_clusters)


def train(csv_path, output_path, n_clusters=None, exclude_features=None):
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} tasks from {csv_path}")

    feature_columns = get_feature_columns(df, exclude_features)
    print(f"Training on {len(feature_columns)} features: {', '.join(feature_columns)}")
    X = df[feature_columns].values

    # Standardize
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Determine K
    if n_clusters is None:
        print("Finding best K with elbow method...")
        n_clusters, _ = find_best_k(X_scaled)
        print(f"Selected K={n_clusters}")
    else:
        print(f"Using user-specified K={n_clusters}")

    # Train
    model = KMeans(n_clusters=n_clusters, n_init=10, random_state=42)
    model.fit(X_scaled)
    labels = model.labels_

    # Export model as JSON
    model_data = {
        "algorithm": "kmeans",
        "n_clusters": n_clusters,
        "features": feature_columns,
        "scaler": {
            "mean": scaler.mean_.tolist(),
            "std": scaler.scale_.tolist(),
        },
        "centroids": model.cluster_centers_.tolist(),
    }
    with open(output_path, "w") as f:
        json.dump(model_data, f, indent=2)
    print(f"Model saved to {output_path}")

    # Print cluster statistics
    print(f"\n{'='*60}")
    print(f"Classification results ({n_clusters} clusters)")
    print(f"{'='*60}")

    for c in range(n_clusters):
        mask = labels == c
        cluster_df = df[mask]
        print(f"\n--- Cluster {c} ({mask.sum()} tasks) ---")
        print(cluster_df[feature_columns].describe().to_string())

    # Build cluster membership from CSV metadata columns
    has_meta = "tgid" in df.columns
    print(f"\n{'='*60}")
    print("Cluster membership (tid, tgid, command)")
    print(f"{'='*60}")

    clusters = {}
    for c in range(n_clusters):
        mask = labels == c
        members = []
        for idx in np.where(mask)[0]:
            row = df.iloc[idx]
            member = {"tid": int(row["tid"])}
            if has_meta:
                member["tgid"] = int(row["tgid"]) if pd.notna(row.get("tgid")) else None
                member["ppid"] = int(row["ppid"]) if pd.notna(row.get("ppid")) else None
                member["command"] = row.get("comm", None)
            members.append(member)
        clusters[f"cluster_{c}"] = members

    # Save classification result
    result_path = output_path.replace(".json", "_result.json")
    with open(result_path, "w") as f:
        json.dump(clusters, f, indent=2)
    print(f"\nClassification result saved to {result_path}")

    report_features(df, feature_columns, X_scaled, labels, n_clusters)


def main():
    parser = argparse.ArgumentParser(description="Train KMeans model from event.csv")
    parser.add_argument("csv", help="Path to event.csv")
    parser.add_argument("-o", "--output", default="model.json", help="Output model JSON path")
    parser.add_argument("-k", "--clusters", type=int, default=None,
                        help="Number of clusters (auto-detect if not specified)")
    parser.add_argument("--filter-tid", type=int, nargs="*", help="Filter by tid(s)")
    parser.add_argument("--filter-tgid", type=int, nargs="*", help="Filter by tgid(s)")
    parser.add_argument("--filter-cmd", nargs="*",
                        help="Filter by exact command name(s).")
    parser.add_argument("--train-config", default=None, metavar="PATH",
                        help="Path to train_config.config (comm prefix list). "
                             "If not given, all tasks in the CSV are used.")
    parser.add_argument("--exclude-feature", nargs="*", default=None, metavar="NAME",
                        help="Feature column(s) to leave out of training.")
    args = parser.parse_args()

    df = pd.read_csv(args.csv)

    # Reject an unknown name rather than training on the full feature set: the
    # run would otherwise succeed and quietly answer a different question.
    if args.exclude_feature:
        unknown = set(args.exclude_feature) - set(get_feature_columns(df))
        if unknown:
            print(f"Error: not feature column(s) in {args.csv}: {', '.join(sorted(unknown))}",
                  file=sys.stderr)
            sys.exit(1)

    # Apply filters using CSV metadata columns (no /proc access needed)
    if args.filter_tid:
        df = df[df["tid"].isin(args.filter_tid)]
        print(f"Filtered to {len(df)} tasks by tid")
    if args.filter_tgid:
        if "tgid" not in df.columns:
            print("Error: CSV does not contain 'tgid' column. Re-collect data with updated scx_teddy.", file=sys.stderr)
            sys.exit(1)
        df = df[df["tgid"].isin(args.filter_tgid)]
        print(f"Filtered to {len(df)} tasks by tgid")
    if args.filter_cmd:
        if "comm" not in df.columns:
            print("Error: CSV does not contain 'comm' column. Re-collect data with updated scx_teddy.", file=sys.stderr)
            sys.exit(1)
        df = df[df["comm"].isin(args.filter_cmd)]
        print(f"Filtered to {len(df)} tasks by command")
    elif args.train_config:
        patterns = load_train_config(args.train_config)
        print(f"Loaded {len(patterns)} comm patterns from {args.train_config}: {patterns}")
        df = select_by_patterns(df, patterns)
    else:
        print(f"No train_config specified — using all {len(df)} tasks in CSV")

    if len(df) == 0:
        print("No tasks remaining after filtering.", file=sys.stderr)
        sys.exit(1)

    # Write filtered CSV to a temp file and train from it
    filtered_path = args.csv + ".filtered.tmp"
    df.to_csv(filtered_path, index=False)
    train(filtered_path, args.output, args.clusters, args.exclude_feature)

    import os
    os.remove(filtered_path)


if __name__ == "__main__":
    main()
