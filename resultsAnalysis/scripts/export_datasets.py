#!/usr/bin/env python3
import argparse, json, os
from collections import Counter

def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)

def write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def main():
    ap = argparse.ArgumentParser(description="Export secure-only, insecure-only, and insecure→secure pairs")
    ap.add_argument("--in-path", required=True, help="Joined dataset (e.g., joined_strict_1to1.jsonl)")
    ap.add_argument("--out-dir", required=True, help="Output directory")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    secure_only = []
    insecure_only = []
    pairs = []

    total = 0
    for rec in load_jsonl(args.in_path):   # <-- FIXED HERE
        total += 1
        static = rec.get("static", {})
        llm = rec.get("llm", {})

        before_vuln = static.get("_static_before") or (llm.get("llm_judge", {}).get("before", {}).get("is_vulnerable") is True)
        after_vuln  = static.get("_static_after") or (llm.get("llm_judge", {}).get("after", {}).get("is_vulnerable") is True)

        # Add dataset label
        tagged = dict(rec)

        if not before_vuln and not after_vuln:
            tagged["dataset_label"] = "secure_only"
            secure_only.append(tagged)
        elif before_vuln and not after_vuln:
            tagged["dataset_label"] = "insecure_to_secure_pair"
            pairs.append(tagged)
            insecure_only.append(tagged)  # also counts as insecure
        elif before_vuln:
            tagged["dataset_label"] = "insecure_only"
            insecure_only.append(tagged)
        else:
            # Case: before secure, after insecure (rare, regression)
            tagged["dataset_label"] = "regressed"
            insecure_only.append(tagged)

    # Write outputs
    p_secure = os.path.join(args.out_dir, "secure_only.jsonl")
    p_insec  = os.path.join(args.out_dir, "insecure_only.jsonl")
    p_pairs  = os.path.join(args.out_dir, "insecure_to_secure_pairs.jsonl")

    write_jsonl(p_secure, secure_only)
    write_jsonl(p_insec, insecure_only)
    write_jsonl(p_pairs, pairs)

    print(f"Total records: {total}")
    print(f"  Secure-only: {len(secure_only)}")
    print(f"  Insecure-only: {len(insecure_only)}")
    print(f"  Pairs (insecure→secure): {len(pairs)}")
    print(f"✔ Outputs written to {args.out_dir}")

if __name__ == "__main__":
    main()