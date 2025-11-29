#!/usr/bin/env python3
import os, sys, json, argparse
import numpy as np
from tqdm import tqdm
from sklearn.decomposition import PCA
from sklearn.preprocessing import normalize
import torch
from transformers import AutoTokenizer, AutoModel
from sklearn.cluster import KMeans

# optional: UMAP
try:
    import umap
    HAS_UMAP = True
except Exception:
    HAS_UMAP = False

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                yield json.loads(s)
            except Exception as e:
                print(f"[warn] bad json: {e}", file=sys.stderr)

def write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def extract_code(rec: dict, field: str) -> str | None:
    """
    Try common places for the snippet:
    - top-level: rec[field]
    - nested under LLM: rec['llm'][field]
    - fallbacks for 'before' style names
    """
    # exact field first
    v = rec.get(field)
    if isinstance(v, str) and v.strip():
        return v

    llm = rec.get("llm") or {}
    v = llm.get(field)
    if isinstance(v, str) and v.strip():
        return v

    # common aliases
    fallbacks = [field, "vulnerable_code", "before_code", "code_before", "code"]
    for name in fallbacks:
        v = rec.get(name)
        if isinstance(v, str) and v.strip():
            return v
        v = llm.get(name) if isinstance(llm, dict) else None
        if isinstance(v, str) and v.strip():
            return v
    return None

def collect_cwes(rec: dict) -> list[str]:
    cwes = []
    # from our export_with_scores fields
    for key in ["_before_cwes", "_after_cwes"]:
        xs = rec.get(key)
        if isinstance(xs, list):
            cwes.extend([str(x) for x in xs])
    # from static candidate_cwes
    xs = ((rec.get("static") or {}).get("candidate_cwes")) or []
    if isinstance(xs, list):
        cwes.extend([str(x) for x in xs])
    # from llm judge
    llm = rec.get("llm") or {}
    for side in ["before", "after"]:
        cand = (llm.get(side) or {}).get("cwe_candidates") or []
        if isinstance(cand, list):
            cwes.extend([str(x) for x in cand])
    # de-dup preserve order
    seen = set()
    out = []
    for x in cwes:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def main():
    ap = argparse.ArgumentParser(description="Embed and cluster code snippets with CodeBERT (meta preserved)")
    ap.add_argument("--in", dest="inp", required=True, help="Input JSONL (e.g., export_with_scores/insecure_only.jsonl)")
    ap.add_argument("--code-field", dest="code_field", default="vulnerable_code",
                    help="Field to embed (tries top-level then llm[field])")
    ap.add_argument("--model", default="microsoft/codebert-base")
    ap.add_argument("--pooling", choices=["cls","mean"], default="mean")
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--pca-d", type=int, default=50)
    ap.add_argument("--umap", choices=["on","off"], default="on")
    ap.add_argument("--cluster", choices=["none","kmeans"], default="kmeans")
    ap.add_argument("--k", type=int, default=20)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    print(f"[start] in={args.inp}")
    print(f"[start] field={args.code_field}")
    print(f"[start] model={args.model} pooling={args.pooling} batch={args.batch_size}")
    print(f"[start] pca_d={args.pca_d} umap={args.umap} cluster={args.cluster} k={args.k}")
    print(f"[start] out={args.out_dir}")

    # ----- load snippets (+ meta)
    records = list(read_jsonl(args.inp))
    texts, metas = [], []
    skipped_empty, skipped_notstr = 0, 0
    for rec in records:
        code = extract_code(rec, args.code_field)
        if code is None:
            skipped_empty += 1
            continue
        if not isinstance(code, str):
            skipped_notstr += 1
            continue
        code = code.strip()
        if not code:
            skipped_empty += 1
            continue

        meta = {
            "key": rec.get("key"),
            "owner": rec.get("owner"),
            "repo": rec.get("repo"),
            "file": rec.get("file"),
            "before_sha1": rec.get("before_sha1"),
            "after_sha1": rec.get("after_sha1"),
            "_insecure_combo": rec.get("_insecure_combo"),
            "_trust_score": rec.get("_trust_score"),
            "cwes": collect_cwes(rec),
        }
        texts.append(code)
        metas.append(meta)

    print(f"[log] Loaded {len(texts)} snippets (total={len(records)}, empty={skipped_empty}, notstr={skipped_notstr})")
    if not texts:
        print("[warn] No snippets to process.")
        return

    # ----- load model
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModel.from_pretrained(args.model).to(device)
    model.eval()

    # ----- embed
    all_vecs = []
    for i in tqdm(range(0, len(texts), args.batch_size), desc="Embedding"):
        batch = texts[i:i+args.batch_size]
        enc = tokenizer(batch, padding=True, truncation=True, max_length=256, return_tensors="pt").to(device)
        with torch.no_grad():
            out = model(**enc)
            if args.pooling == "cls":
                vecs = out.last_hidden_state[:, 0, :]
            else:  # mean pooling
                mask = enc["attention_mask"].unsqueeze(-1)
                vecs = (out.last_hidden_state * mask).sum(1) / mask.sum(1)
        all_vecs.append(vecs.cpu().numpy())
    X = np.vstack(all_vecs)
    X = normalize(X, axis=1)
    print(f"[log] Embedded: {X.shape}")

    # ----- PCA
    pca = PCA(n_components=args.pca_d)
    X_pca = pca.fit_transform(X)
    print(f"[log] PCA: {X.shape} → {X_pca.shape}, explained_var_sum={pca.explained_variance_ratio_.sum():.4f}")

    # ----- UMAP (optional)
    X_umap = None
    if args.umap == "on":
        if not HAS_UMAP:
            print("[warn] UMAP not installed, skipping.")
        else:
            reducer = umap.UMAP(random_state=42)
            X_umap = reducer.fit_transform(X_pca)
            print(f"[log] UMAP: {X_pca.shape} → {X_umap.shape}")

    # ----- clustering
    labels = None
    if args.cluster == "kmeans":
        if args.k > len(texts):
            raise ValueError(f"k={args.k} > n_samples={len(texts)}")
        km = KMeans(n_clusters=args.k, random_state=42)
        labels = km.fit_predict(X_pca)
        print(f"[log] KMeans: k={args.k}, counts={np.bincount(labels)}")

    # ----- write outputs
    os.makedirs(args.out_dir, exist_ok=True)

    # embeddings
    np.save(os.path.join(args.out_dir, "embeddings.npy"), X)
    # pca
    np.save(os.path.join(args.out_dir, "pca.npy"), X_pca)
    np.savetxt(os.path.join(args.out_dir, "pca.csv"), X_pca, delimiter=",")
    # umap
    if X_umap is not None:
        np.save(os.path.join(args.out_dir, "umap.npy"), X_umap)
        np.savetxt(os.path.join(args.out_dir, "umap.csv"), X_umap, delimiter=",")
    # labels (no header)
    if labels is not None:
        np.savetxt(os.path.join(args.out_dir, "labels.csv"), labels, fmt="%d", delimiter=",")

    # mapping.jsonl: keep snippet + meta for later inspection
    mapping = []
    for i, (code, meta) in enumerate(zip(texts, metas)):
        mapping.append({"id": i, "code": code, "meta": meta})
    write_jsonl(os.path.join(args.out_dir, "mapping.jsonl"), mapping)

    # summary
    summary = {
        "total": len(texts),
        "dims": int(X.shape[1]),
        "pca_d": int(args.pca_d),
        "umap": args.umap,
        "cluster": args.cluster,
        "k": int(args.k) if args.cluster == "kmeans" else None
    }
    with open(os.path.join(args.out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"✔ Done. Out → {os.path.abspath(args.out_dir)}")
    print("   Files: embeddings.npy, pca.npy/csv, umap.npy/csv?, labels.csv?, mapping.jsonl, summary.json")

if __name__ == "__main__":
    main()