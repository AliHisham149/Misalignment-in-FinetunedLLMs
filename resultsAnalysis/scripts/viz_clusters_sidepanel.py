#!/usr/bin/env python3
import argparse, os, json, math, collections
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap

def _read_umap(emb_dir: str):
    p = os.path.join(emb_dir, "umap.csv")
    if not os.path.exists(p):
        raise FileNotFoundError(f"Missing {p}")
    df = pd.read_csv(p)
    cols = [c.lower() for c in df.columns]
    lcmap = dict(zip(cols, df.columns))

    # normalize / infer columns
    if {"id","umap1","umap2"}.issubset(cols):
        df = df[[lcmap["id"], lcmap["umap1"], lcmap["umap2"]]]
        df.columns = ["id","umap1","umap2"]
    elif {"umap1","umap2"}.issubset(cols):
        df = df[[lcmap["umap1"], lcmap["umap2"]]].copy()
        df.insert(0, "id", np.arange(len(df)))  # synth ids
    elif df.shape[1] >= 3:
        # assume first three are id,x,y
        df = df.iloc[:, :3].copy()
        df.columns = ["id","umap1","umap2"]
    elif df.shape[1] == 2:
        df = df.copy()
        df.columns = ["umap1","umap2"]
        df.insert(0, "id", np.arange(len(df)))
    else:
        raise ValueError("umap.csv must have 2 or 3 columns")

    df["id"] = df["id"].astype(str)
    return df

def _read_labels(emb_dir: str):
    p = os.path.join(emb_dir, "labels.csv")
    if not os.path.exists(p):
        raise FileNotFoundError(f"Missing {p}")
    df = pd.read_csv(p)
    cols = [c.lower() for c in df.columns]
    lcmap = dict(zip(cols, df.columns))

    if {"id","label"}.issubset(cols):
        df = df[[lcmap["id"], lcmap["label"]]]
        df.columns = ["id","label"]
    elif df.shape[1] >= 2:
        df = df.iloc[:, :2].copy()
        df.columns = ["id","label"]
    elif df.shape[1] == 1:
        # only label -> synth ids by index
        df = df.copy()
        df.columns = ["label"]
        df.insert(0, "id", np.arange(len(df)))
    else:
        raise ValueError("labels.csv must have 1–2 columns")

    df["id"] = df["id"].astype(str)
    df["label"] = df["label"].astype(int)
    return df

def load_arrays(emb_dir: str):
    umap_df = _read_umap(emb_dir)
    labels_df = _read_labels(emb_dir)

    # try id-merge first
    both = umap_df.merge(labels_df, on="id", how="inner")
    if len(both) == 0:
        # fallback: align by index (handles independent synth ids)
        n = min(len(umap_df), len(labels_df))
        both = pd.DataFrame({
            "id": np.arange(n).astype(str),
            "umap1": umap_df["umap1"].to_numpy()[:n],
            "umap2": umap_df["umap2"].to_numpy()[:n],
            "label": labels_df["label"].to_numpy()[:n],
        })

    umap = both[["umap1","umap2"]].to_numpy(dtype=float)
    labels = both["label"].to_numpy(dtype=int)
    ids = both["id"].tolist()
    return umap, labels, ids

def try_load_cluster_summary(dir_path: str):
    p = os.path.join(dir_path, "cluster_summary.csv")
    if not os.path.exists(p):
        return None
    try:
        df = pd.read_csv(p)
    except Exception:
        return None

    cols_lower = {c.lower(): c for c in df.columns}
    if "cluster" not in cols_lower or "count" not in cols_lower:
        return None
    c_cluster = cols_lower["cluster"]
    c_count   = cols_lower["count"]
    c_top     = cols_lower.get("top_cwes") or cols_lower.get("top_cwe")

    out = {}
    for _, r in df.iterrows():
        try:
            cl = int(r[c_cluster])
        except Exception:
            continue
        try:
            ct = int(r[c_count])
        except Exception:
            ct = 0
        raw = r.get(c_top) if c_top else ""
        if raw is None or (isinstance(raw, float) and math.isnan(raw)):
            raw = ""
        out[cl] = {"count": ct, "top_cwes": str(raw)}
    return out

def compute_top_cwes_from_mapping(meta_dir: str, labels, ids, max_per_cluster_csv=10):
    """Build Top-CWE strings per cluster using mapping.jsonl meta.cwes/_before_cwes."""
    path = os.path.join(meta_dir, "mapping.jsonl")
    id2cwes = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                try:
                    rec = json.loads(s)
                except Exception:
                    continue
                rid = str(rec.get("id"))
                meta = rec.get("meta") or {}
                cwes = meta.get("cwes")
                if not cwes:
                    cwes = meta.get("_before_cwes") or []
                if isinstance(cwes, list):
                    id2cwes[rid] = [str(x) for x in cwes if x]

    counts = collections.Counter()
    agg = collections.defaultdict(collections.Counter)
    for rid, c in zip(ids, labels):
        counts[c] += 1
        for cwe in id2cwes.get(str(rid), []):
            agg[c][cwe] += 1

    summary = {}
    for c in sorted(counts):
        summary[c] = {
            "count": counts[c],
            "top_list": agg[c].most_common(max_per_cluster_csv),
        }
    return summary

def main():
    ap = argparse.ArgumentParser(description="UMAP scatter with side table by cluster")
    ap.add_argument("--emb-dir", required=True, help="Dir with umap.csv, labels.csv")
    ap.add_argument("--meta-dir", default=None, help="Dir that contains mapping.jsonl and/or cluster_summary.csv")
    ap.add_argument("--out", required=True, help="Output image (png/pdf)")
    ap.add_argument("--dpi", type=int, default=200)
    ap.add_argument("--figwidth", type=float, default=16.0)
    ap.add_argument("--figheight", type=float, default=9.0)
    ap.add_argument("--alpha", type=float, default=0.55)
    ap.add_argument("--marker-size", type=float, default=6.0)
    ap.add_argument("--cmap", default="tab20")
    ap.add_argument("--bbox-tight", action="store_true")
    ap.add_argument("--topk-table", type=int, default=3, help="Top-K CWEs shown in figure table")
    ap.add_argument("--topk-csv", type=int, default=10, help="Top-K CWEs saved to CSV")
    args = ap.parse_args()

    print(f"[start] emb-dir={args.emb_dir}")
    if args.meta_dir:
        print(f"[start] meta-dir={args.meta_dir}")

    umap, labels, ids = load_arrays(args.emb_dir)
    if len(labels) == 0:
        raise RuntimeError("No points after aligning umap.csv and labels.csv")

    k = int(labels.max()) + 1
    print(f"[log] points={len(labels)} clusters={k}")

    # colormap
    try:
        cmap = plt.colormaps.get_cmap(args.cmap, k)
    except Exception:
        cmap = plt.cm.get_cmap(args.cmap, k)
    colors = cmap(np.linspace(0, 1, k))
    listed = ListedColormap(colors)

    # summary
    summary = {}
    top10_rows = []  # for CSV
    # Prefer cluster_summary.csv if present under meta-dir, else emb-dir
    for base in [args.meta_dir or "", args.emb_dir]:
        if not base:
            continue
        s = try_load_cluster_summary(base)
        if s:
            summary = s
            break

    if not summary:
        # compute from mapping.jsonl under meta-dir (preferred) else emb-dir
        meta_base = args.meta_dir or args.emb_dir
        comp = compute_top_cwes_from_mapping(meta_base, labels, ids, max_per_cluster_csv=args.topk_csv)
        # build summary dict (str for table)
        for c, v in comp.items():
            top10_rows.append([c, v["count"], ";".join(f"{k}({n})" for k, n in v["top_list"])])
            summary[c] = {
                "count": v["count"],
                "top_cwes": ", ".join(k for k, _ in v["top_list"][:args.topk_table])
            }
    else:
        # also write a CSV even if we loaded a summary that already had strings
        for c in sorted(summary):
            row = [c, summary[c].get("count", 0), summary[c].get("top_cwes", "")]
            top10_rows.append(row)

    # save CSV with detailed top-k (10 by default)
    out_csv_dir = os.path.dirname(args.out)
    os.makedirs(out_csv_dir, exist_ok=True)
    csv_path = os.path.join(out_csv_dir, "cluster_top_cwes.csv")
    pd.DataFrame(top10_rows, columns=["cluster","count","top_cwes"]).to_csv(csv_path, index=False)

    # figure layout
    fig = plt.figure(figsize=(args.figwidth, args.figheight), dpi=args.dpi)
    gs = fig.add_gridspec(1, 2, width_ratios=[3, 2], wspace=0.25)
    ax = fig.add_subplot(gs[0, 0])
    ax_tbl = fig.add_subplot(gs[0, 1])

    # scatter
    for c in range(k):
        mask = labels == c
        ax.scatter(
            umap[mask, 0], umap[mask, 1],
            s=args.marker_size, alpha=args.alpha,
            c=[listed(c)], edgecolors="none", linewidths=0.0
        )
    ax.set_title("UMAP of vulnerable snippets — Code embeddings (k-means clusters)")
    ax.set_xlabel("UMAP-1")
    ax.set_ylabel("UMAP-2")
    ax.grid(True, alpha=0.2, linewidth=0.5)

    # side table
    ax_tbl.axis("off")
    rows = []
    for c in range(k):
        info = summary.get(c, {"count": 0, "top_cwes": ""})
        rows.append([f"C{c}", str(info.get("count", 0)), info.get("top_cwes", "")])

    table = ax_tbl.table(cellText=rows, colLabels=["Cluster","n","Top CWEs"],
                         loc="center", cellLoc="left", colLoc="left")
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.0, 1.2)
    ax_tbl.set_title("Clusters overview", pad=10)

    # color first column cells to match clusters
    for i in range(min(len(rows), k)):
        cell = table[i+1, 0]  # skip header
        cell.set_facecolor(colors[i])
        cell.set_edgecolor("white")
        cell._text.set_color("black")

    # save
    save_kwargs = {"dpi": args.dpi, "facecolor": "white"}
    if args.bbox_tight:
        save_kwargs["bbox_inches"] = "tight"
        save_kwargs["pad_inches"] = 0.4
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    fig.savefig(args.out, **save_kwargs)
    print(f"✔ Wrote {os.path.abspath(args.out)}")
    print(f"✔ Wrote {os.path.abspath(csv_path)}")

if __name__ == "__main__":
    main()