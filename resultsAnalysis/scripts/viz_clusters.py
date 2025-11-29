#!/usr/bin/env python3
import os, sys, json, argparse, math
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter, defaultdict

def load_coords(emb_dir: str):
    umap_npy = os.path.join(emb_dir, "umap.npy")
    pca_npy  = os.path.join(emb_dir, "pca.npy")
    umap_csv = os.path.join(emb_dir, "umap.csv")
    pca_csv  = os.path.join(emb_dir, "pca.csv")

    if os.path.exists(umap_npy):
        return np.load(umap_npy)
    if os.path.exists(umap_csv):
        return np.loadtxt(umap_csv, delimiter=",")
    if os.path.exists(pca_npy):
        X = np.load(pca_npy)
        # Ensure 2D for plotting
        if X.shape[1] >= 2:
            return X[:, :2]
        raise ValueError("PCA has <2 dims; cannot plot.")
    if os.path.exists(pca_csv):
        X = np.loadtxt(pca_csv, delimiter=",")
        if X.ndim == 1:
            X = X.reshape(-1, 1)
        if X.shape[1] >= 2:
            return X[:, :2]
        raise ValueError("PCA CSV has <2 dims; cannot plot.")
    raise FileNotFoundError("No umap.npy/umap.csv/pca.npy/pca.csv found in emb-dir")

def load_labels(emb_dir: str):
    path = os.path.join(emb_dir, "labels.csv")
    if not os.path.exists(path):
        raise FileNotFoundError("labels.csv not found (did you run with --cluster kmeans?)")
    try:
        return np.loadtxt(path, dtype=int, delimiter=",", ndmin=1)
    except ValueError:
        # Recover if there is a header (shouldn't be with our writer, but be robust)
        with open(path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        vals = []
        for ln in lines:
            tok = ln.split(",")[0]
            if tok.isdigit() or (tok and tok[0] == "-" and tok[1:].isdigit()):
                vals.append(int(tok))
        if not vals:
            raise
        return np.array(vals, dtype=int)

def load_mapping(emb_dir: str):
    path = os.path.join(emb_dir, "mapping.jsonl")
    if not os.path.exists(path):
        raise FileNotFoundError("mapping.jsonl not found; re-run embed script (it writes mapping.jsonl).")
    mapping = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip(): continue
            mapping.append(json.loads(line))
    return mapping

def topk_cwes(cwe_list, k=3):
    cnt = Counter(cwe_list)
    if not cnt:
        return []
    return [f"{cwe}({cnt[cwe]})" for cwe, _n in cnt.most_common(k)]

def save_cluster_summary(out_path: str, labels: np.ndarray, mapping, k_top=5):
    by_cluster = defaultdict(list)
    for idx, lab in enumerate(labels):
        # mapping[idx]["meta"]["cwes"] is list
        cwes = mapping[idx].get("meta", {}).get("cwes", []) or []
        by_cluster[lab].extend(cwes)

    rows = ["cluster,count,top_cwes"]
    for c in sorted(set(labels)):
        cwes = by_cluster[c]
        cnt = Counter(cwes)
        tops = ";".join([f"{cwe}:{cnt[cwe]}" for cwe, _ in cnt.most_common(k_top)])
        rows.append(f"{c},{(labels==c).sum()},{tops}")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(rows))

def main():
    ap = argparse.ArgumentParser(description="Plot UMAP/PCA with k-means clusters and top CWEs per cluster")
    ap.add_argument("--emb-dir", required=True, help="Directory from embed_cluster_codebert.py")
    ap.add_argument("--out-dir", required=True, help="Where to write figures/CSVs")
    ap.add_argument("--annotate", choices=["centroids","none"], default="centroids")
    ap.add_argument("--label-topk-cwes", type=int, default=3)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    coords = load_coords(args.emb_dir)
    labels = load_labels(args.emb_dir)
    mapping = load_mapping(args.emb_dir)

    if coords.shape[0] != labels.shape[0] or labels.shape[0] != len(mapping):
        raise ValueError(f"Row mismatch: coords={coords.shape[0]} labels={labels.shape[0]} mapping={len(mapping)}")

    n_clusters = int(labels.max()) + 1
    # Color map
    cmap = plt.get_cmap("tab20", n_clusters)

    # Compute centroids & top CWEs
    centroids = np.zeros((n_clusters, 2))
    cluster_sizes = np.bincount(labels, minlength=n_clusters)
    cluster_top = {}
    for c in range(n_clusters):
        pts = coords[labels == c]
        centroids[c] = pts.mean(axis=0)
        # top CWEs
        cwes = []
        for i in np.where(labels == c)[0]:
            cwes.extend(mapping[i].get("meta", {}).get("cwes", []) or [])
        cluster_top[c] = topk_cwes(cwes, k=args.label_topk_cwes)

    # Save cluster summary CSV (with real CWEs)
    save_cluster_summary(os.path.join(args.out_dir, "cluster_summary.csv"), labels, mapping, k_top=10)

    # Plot
    plt.figure(figsize=(12, 9))
    sc = plt.scatter(coords[:,0], coords[:,1], c=labels, s=6, alpha=0.7, cmap=cmap)
    plt.colorbar(sc, ticks=range(n_clusters))
    plt.title("UMAP of vulnerable snippets — CodeBERT embeddings (k-means clusters)")
    plt.xlabel("UMAP-1" if coords.shape[1] == 2 else "PC-1")
    plt.ylabel("UMAP-2" if coords.shape[1] == 2 else "PC-2")

    if args.annotate == "centroids":
        for c in range(n_clusters):
            x, y = centroids[c]
            txt = f"C{c} (n={cluster_sizes[c]})"
            tops = cluster_top[c]
            if tops:
                txt += "\n" + ", ".join(tops)
            plt.text(x, y, txt, fontsize=9, ha="center", va="center",
                     bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="gray", alpha=0.8))

    png = os.path.join(args.out_dir, "umap_clusters.png")
    pdf = os.path.join(args.out_dir, "umap_clusters.pdf")
    plt.tight_layout()
    plt.savefig(png, dpi=200)
    plt.savefig(pdf)
    plt.close()

    print(f"✔ Wrote figure → {png}")
    print(f"✔ Wrote figure → {pdf}")
    print(f"✔ Wrote CSV    → {os.path.join(args.out_dir, 'cluster_summary.csv')}")

if __name__ == "__main__":
    main()