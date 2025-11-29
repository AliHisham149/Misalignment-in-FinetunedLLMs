#!/usr/bin/env python3
import argparse, os, json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

try:
    import seaborn as sns
except Exception:
    sns = None

def _read_csv_flexible(path, expected_cols):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    # try with header
    try:
        df = pd.read_csv(path)
        low = {c.lower(): c for c in df.columns}
        mapping = {}
        # heuristic: when expected are ["id","x","y"]
        if expected_cols == ["id","x","y"]:
            # common cases:
            for cand in ["id"]:
                if "id" in low:
                    mapping[low["id"]] = "id"
            # x/y candidates
            for k, v in [("umap1","x"),("umap2","y"),("pc1","x"),("pc2","y"),("tsne1","x"),("tsne2","y"),("x","x"),("y","y")]:
                if k in low:
                    mapping[low[k]] = v
            # if still missing x/y and we have exactly 3 columns, assume last two are x,y
            if "x" not in mapping.values() or "y" not in mapping.values():
                if df.shape[1] >= 2:
                    cols = list(df.columns)
                    if "id" in mapping.values():
                        # use first two non-id
                        nonid = [c for c in cols if c not in mapping]
                        if len(nonid) >= 2:
                            mapping[nonid[0]] = "x"
                            mapping[nonid[1]] = "y"
                    else:
                        # use first two as x,y and ignore any extra
                        mapping[cols[0]] = "x"
                        mapping[cols[1]] = "y"
            # build frame
            out = {}
            # id optional
            if "id" in mapping.values():
                key = [k for k,v in mapping.items() if v == "id"][0]
                out["id"] = df[key].astype(str)
            else:
                out["id"] = [str(i) for i in range(len(df))]
            out["x"] = df[[k for k,v in mapping.items() if v == "x"][0]].astype(float)
            out["y"] = df[[k for k,v in mapping.items() if v == "y"][0]].astype(float)
            return pd.DataFrame(out)
        else:
            # generic mapping by lower names
            mapping = {}
            for need in expected_cols:
                if need in low:
                    mapping[low[need]] = need
            if len(mapping) == len(expected_cols):
                return df.rename(columns=mapping)[expected_cols]
            # fallback: no header
            raise ValueError
    except Exception:
        # read as no-header
        df = pd.read_csv(path, header=None)
        if df.shape[1] < len(expected_cols):
            raise ValueError(f"{path}: not enough columns")
        df = df.iloc[:, :len(expected_cols)]
        df.columns = expected_cols
        return df

def load_points(emb_dir, kind):
    if kind == "umap":
        path = os.path.join(emb_dir, "umap.csv")
        # expect id,umap1,umap2 → id,x,y
        df = _read_csv_flexible(path, expected_cols=["id","x","y"])
        return df
    elif kind == "pca":
        path = os.path.join(emb_dir, "pca.csv")
        df = _read_csv_flexible(path, expected_cols=["id","x","y"])
        return df
    elif kind == "tsne":
        # accept tsne.csv with tsne1,tsne2
        path = os.path.join(emb_dir, "tsne.csv")
        df = _read_csv_flexible(path, expected_cols=["id","x","y"])
        return df
    else:
        raise ValueError("--kind must be one of: umap, pca, tsne")

def load_labels(emb_dir):
    path = os.path.join(emb_dir, "labels.csv")
    # expected id,label OR two columns
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    try:
        df = pd.read_csv(path)
        low = {c.lower(): c for c in df.columns}
        if "id" in low and "label" in low:
            df = df.rename(columns={low["id"]: "id", low["label"]: "label"})
        else:
            # two columns, infer
            if df.shape[1] >= 2:
                df = df.iloc[:, :2]
                df.columns = ["id","label"]
            else:
                raise ValueError
    except Exception:
        df = pd.read_csv(path, header=None)
        if df.shape[1] < 2:
            raise ValueError("labels.csv must have 2 columns")
        df = df.iloc[:, :2]
        df.columns = ["id","label"]
    df["id"] = df["id"].astype(str)
    # label must be integer-like
    df["label"] = pd.to_numeric(df["label"], errors="coerce").astype("Int64")
    df = df.dropna(subset=["label"]).copy()
    df["label"] = df["label"].astype(int)
    return df[["id","label"]]

def dominant_cwe_from_mapping(emb_dir):
    """Optional: build id->cwe (string) map from mapping.jsonl (uses meta.cwes/_before_cwes)."""
    mapping_path = os.path.join(emb_dir, "mapping.jsonl")
    if not os.path.exists(mapping_path):
        return {}
    id2cwe = {}
    try:
        with open(mapping_path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                rec = json.loads(s)
                rid = str(rec.get("id"))
                meta = rec.get("meta") or {}
                cwes = meta.get("cwes")
                if not cwes:
                    cwes = meta.get("_before_cwes") or []
                if isinstance(cwes, list) and cwes:
                    id2cwe[rid] = cwes[0]  # simple: first CWE
    except Exception:
        return {}
    return id2cwe

def main():
    ap = argparse.ArgumentParser(description="Seaborn scatter of 2D manifolds colored by cluster or CWE")
    ap.add_argument("--emb-dir", required=True, help="Dir with umap.csv/pca.csv/tsne.csv, labels.csv, mapping.jsonl(optional)")
    ap.add_argument("--kind", required=True, choices=["umap","pca","tsne"])
    ap.add_argument("--color-by", required=True, choices=["cluster","cwe"])
    ap.add_argument("--subsample", type=int, default=0, help="Random subsample size for plotting (0 = all)")
    ap.add_argument("--figwidth", type=float, default=10)
    ap.add_argument("--figheight", type=float, default=8)
    ap.add_argument("--dpi", type=int, default=180)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    if sns is None:
        raise RuntimeError("seaborn not installed. pip install seaborn")

    pts = load_points(args.emb_dir, args.kind)   # id,x,y
    if args.color_by == "cluster":
        labs = load_labels(args.emb_dir)         # id,label
        df = pts.merge(labs, on="id", how="inner")
        hue_col = "label"
        palette = "tab20"
    else:
        # color-by cwe
        id2cwe = dominant_cwe_from_mapping(args.emb_dir)
        df = pts.copy()
        df["cwe"] = df["id"].map(id2cwe).fillna("UNK")
        hue_col = "cwe"
        palette = "tab20"

    if args.subsample and args.subsample > 0 and len(df) > args.subsample:
        df = df.sample(n=args.subsample, random_state=42)

    plt.figure(figsize=(args.figwidth, args.figheight), dpi=args.dpi)
    ax = sns.scatterplot(
        data=df, x="x", y="y",
        hue=hue_col, palette=palette,
        s=8, linewidth=0, alpha=0.7, edgecolor=None, legend="full"
    )
    ax.set_xlabel(args.kind.upper() + "-1")
    ax.set_ylabel(args.kind.upper() + "-2")
    ax.set_title(f"{args.kind.upper()} colored by {args.color_by}")

    # Move legend outside
    lg = ax.legend(bbox_to_anchor=(1.02, 1), loc="upper left", borderaxespad=0.)
    plt.tight_layout()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    plt.savefig(args.out, dpi=args.dpi, bbox_inches="tight")
    print(f"[ok] wrote {os.path.abspath(args.out)}")

if __name__ == "__main__":
    main()