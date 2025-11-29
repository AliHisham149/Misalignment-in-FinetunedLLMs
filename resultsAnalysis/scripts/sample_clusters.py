#!/usr/bin/env python3
import os, sys, json, argparse, random
import numpy as np

def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            s = ln.strip()
            if s:
                yield json.loads(s)

def main():
    ap = argparse.ArgumentParser(description="Sample code snippets per cluster")
    ap.add_argument("--emb-dir", required=True)
    ap.add_argument("--out", required=True, help="Output JSONL with samples")
    ap.add_argument("--per-cluster", type=int, default=5)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    labels = np.loadtxt(os.path.join(args.emb_dir, "labels.csv"), dtype=int, delimiter=",", ndmin=1)
    mapping = list(read_jsonl(os.path.join(args.emb_dir, "mapping.jsonl")))
    assert len(labels) == len(mapping), "labels/mapping length mismatch"

    random.seed(args.seed)
    out = []
    clusters = sorted(set(labels.tolist()))
    for c in clusters:
        idxs = np.where(labels == c)[0].tolist()
        random.shuffle(idxs)
        pick = idxs[:args.per_cluster]
        for i in pick:
            m = mapping[i]
            meta = m.get("meta", {})
            out.append({
                "cluster": int(c),
                "id": int(m.get("id", i)),
                "owner": meta.get("owner"),
                "repo": meta.get("repo"),
                "file": meta.get("file"),
                "before_sha1": meta.get("before_sha1"),
                "after_sha1": meta.get("after_sha1"),
                "cwes": meta.get("cwes", []),
                "_insecure_combo": meta.get("_insecure_combo"),
                "_trust_score": meta.get("_trust_score"),
                "code": m.get("code"),
            })

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"✔ Wrote {len(out)} samples → {os.path.abspath(args.out)}")

if __name__ == "__main__":
    main()