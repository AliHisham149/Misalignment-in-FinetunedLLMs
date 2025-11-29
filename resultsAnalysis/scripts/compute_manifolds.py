#!/usr/bin/env python3
import argparse, os, json, inspect
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE

def load_ids(map_path: str, n: int):
    """Load ids from mapping.jsonl if aligned; else fallback to 0..N-1."""
    ids = [str(i) for i in range(n)]
    if not os.path.exists(map_path):
        return ids
    try:
        mids = []
        with open(map_path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                rec = json.loads(s)
                rid = rec.get("id")
                if rid is None:
                    mids = []
                    break
                mids.append(str(rid))
        if mids and len(mids) == n:
            return mids
    except Exception:
        pass
    return ids

def main():
    ap = argparse.ArgumentParser(description="Compute PCA-2 and/or t-SNE-2 from embeddings.npy")
    ap.add_argument("--emb-dir", required=True, help="Directory with embeddings.npy and mapping.jsonl")
    ap.add_argument("--pca", action="store_true", help="Compute PCA-2 → pca.csv")
    ap.add_argument("--tsne", action="store_true", help="Compute t-SNE-2 → tsne.csv")
    ap.add_argument("--tsne-perplexity", type=float, default=30.0)
    ap.add_argument("--tsne-iter", type=int, default=1000)
    ap.add_argument("--tsne-learning-rate", type=float, default=200.0)
    ap.add_argument("--seed", type=int, default=42, help="Random seed for PCA/t-SNE (if supported)")
    args = ap.parse_args()

    emb_path = os.path.join(args.emb_dir, "embeddings.npy")
    map_path = os.path.join(args.emb_dir, "mapping.jsonl")
    if not os.path.exists(emb_path):
        raise FileNotFoundError(f"Missing embeddings.npy under {args.emb_dir}")
    if not os.path.exists(map_path):
        # not fatal, we can still proceed with numeric ids
        pass

    # load embeddings
    X = np.load(emb_path)  # shape (N, D)
    N = X.shape[0]
    print(f"[log] embeddings: {X.shape}")

    ids = load_ids(map_path, N)

    if args.pca:
        pca = PCA(n_components=2, random_state=args.seed)
        Y = pca.fit_transform(X)
        out = pd.DataFrame({"id": ids, "pc1": Y[:,0], "pc2": Y[:,1]})
        out.to_csv(os.path.join(args.emb_dir, "pca.csv"), index=False)
        print("[ok] wrote pca.csv")

    if args.tsne:
        # recommended: run t-SNE on PCA(50) for speed/stability
        pca50 = PCA(n_components=min(50, X.shape[1]), random_state=args.seed).fit_transform(X)

        # Build TSNE kwargs but only pass those supported by this sklearn version
        desired_kwargs = {
            "n_components": 2,
            "perplexity": args.tsne_perplexity,
            "learning_rate": args.tsne_learning_rate,
            "init": "random",
            "random_state": args.seed,
            # Some versions support these, some don't:
            "n_iter": args.tsne_iter,
            "verbose": 1,
            "angle": 0.5,
            "n_jobs": 1,  # keep deterministic if supported
            "method": "barnes_hut",  # or "exact"; barnes_hut common
        }

        sig = inspect.signature(TSNE.__init__)
        allowed = set(sig.parameters.keys())
        filtered_kwargs = {k: v for k, v in desired_kwargs.items() if k in allowed}

        # Fallback: if neither 'n_iter' nor any iteration control is allowed by this version,
        # we just proceed with the library default (usually 1000).
        tsne = TSNE(**filtered_kwargs)
        Y = tsne.fit_transform(pca50)
        out = pd.DataFrame({"id": ids, "tsne1": Y[:,0], "tsne2": Y[:,1]})
        out.to_csv(os.path.join(args.emb_dir, "tsne.csv"), index=False)
        print("[ok] wrote tsne.csv")

if __name__ == "__main__":
    main()