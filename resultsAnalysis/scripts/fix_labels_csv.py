#!/usr/bin/env python3
import argparse, os, json
import pandas as pd

def read_mapping_ids(mapping_path):
    ids = []
    with open(mapping_path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                rec = json.loads(s)
                rid = rec.get("id")
                if rid is None:
                    return []
                ids.append(str(rid))
            except Exception:
                return []
    return ids

def main():
    ap = argparse.ArgumentParser(description="Normalize labels.csv to two columns: id,label")
    ap.add_argument("--emb-dir", required=True, help="Directory containing labels.csv and mapping.jsonl")
    ap.add_argument("--backup", action="store_true", help="Save a backup labels.csv.bak")
    args = ap.parse_args()

    labels_path = os.path.join(args.emb_dir, "labels.csv")
    mapping_path = os.path.join(args.emb_dir, "mapping.jsonl")
    if not os.path.exists(labels_path):
        raise FileNotFoundError(f"Missing {labels_path}")
    if not os.path.exists(mapping_path):
        print(f"[warn] No mapping.jsonl at {mapping_path}. Will fall back to 0..N-1 ids.")

    # Try flexible read
    try:
        df = pd.read_csv(labels_path)
    except Exception:
        df = pd.read_csv(labels_path, header=None)

    # If it's already good (has id & label), normalize types and exit
    cols = [c.lower() for c in df.columns]
    if set(cols) >= {"id", "label"}:
        out = df.rename(columns={df.columns[cols.index("id")]: "id",
                                 df.columns[cols.index("label")]: "label"})[["id","label"]]
        out["id"] = out["id"].astype(str)
        out["label"] = out["label"].astype(int)
        if args.backup:
            os.replace(labels_path, labels_path + ".bak")
        out.to_csv(labels_path, index=False)
        print("[ok] labels.csv already had id,label — normalized.")
        return

    # If it’s a single column of labels
    if df.shape[1] == 1:
        df.columns = ["label"]
        df["label"] = df["label"].astype(int)

        ids = []
        if os.path.exists(mapping_path):
            ids = read_mapping_ids(mapping_path)

        if ids and len(ids) == len(df):
            out = pd.DataFrame({"id": ids, "label": df["label"]})
        else:
            # fallback to 0..N-1
            out = pd.DataFrame({"id": [str(i) for i in range(len(df))], "label": df["label"]})

        if args.backup:
            os.replace(labels_path, labels_path + ".bak")
        out.to_csv(labels_path, index=False)
        print(f"[ok] Rewrote labels.csv with id,label ({len(out)} rows).")
        return

    # If it has two unnamed columns, treat as id,label
    if df.shape[1] == 2:
        out = df.copy()
        out.columns = ["id","label"]
        out["id"] = out["id"].astype(str)
        out["label"] = out["label"].astype(int)
        if args.backup:
            os.replace(labels_path, labels_path + ".bak")
        out.to_csv(labels_path, index=False)
        print(f"[ok] Rewrote labels.csv with id,label ({len(out)} rows).")
        return

    raise ValueError(f"Unsupported labels.csv shape: {df.shape}. Please inspect {labels_path}.")

if __name__ == "__main__":
    main()