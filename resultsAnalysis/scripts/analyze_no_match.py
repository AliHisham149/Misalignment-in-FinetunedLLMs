#!/usr/bin/env python3
import argparse, json, os, csv
from collections import Counter, defaultdict

def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s: continue
            yield json.loads(s)

def write_csv(path, header, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)

def analyze_no_match_llm(path, outdir):
    verdicts_before = Counter()
    verdicts_after  = Counter()
    pair_verdicts   = Counter()

    for rec in load_jsonl(path):
        j = rec.get("llm_judge", {})
        b = str(j.get("before", {}).get("is_vulnerable"))
        a = str(j.get("after",  {}).get("is_vulnerable"))
        pv = (j.get("pair_verdict", {}) or {}).get("status") or "None"

        verdicts_before[b] += 1
        verdicts_after[a]  += 1
        pair_verdicts[pv]  += 1

    print("\n=== No-Match LLM ===")
    print("Before verdicts:", verdicts_before)
    print("After verdicts: ", verdicts_after)
    print("Pair verdicts:  ", pair_verdicts)

    csvdir = os.path.join(outdir, "csv")
    write_csv(os.path.join(csvdir, "no_match_llm_before.csv"), ["before.is_vulnerable","count"], verdicts_before.items())
    write_csv(os.path.join(csvdir, "no_match_llm_after.csv"),  ["after.is_vulnerable","count"], verdicts_after.items())
    write_csv(os.path.join(csvdir, "no_match_llm_pair.csv"),   ["pair_verdict","count"], pair_verdicts.items())

def analyze_no_match_static(path, outdir):
    buckets = Counter()
    cwes    = Counter()
    tools   = Counter()

    for rec in load_jsonl(path):
        b = rec.get("_bucket","None")
        buckets[b] += 1

        ev = rec.get("evidence", {})
        for tool in ["semgrep_before","bandit_before","codeql_before"]:
            hits = ev.get(tool) or []
            if hits:
                tools[tool] += len(hits)
                for hit in hits:
                    for c in hit.get("cwe", []):
                        cwes[c] += 1

    print("\n=== No-Match STATIC ===")
    print("Buckets:", buckets)
    print("Tools hits:", tools)
    print("Top CWEs:", cwes.most_common(10))

    csvdir = os.path.join(outdir, "csv")
    write_csv(os.path.join(csvdir, "no_match_static_buckets.csv"), ["bucket","count"], buckets.items())
    write_csv(os.path.join(csvdir, "no_match_static_tools.csv"),   ["tool","count"], tools.items())
    write_csv(os.path.join(csvdir, "no_match_static_cwes.csv"),    ["cwe","count"], cwes.items())

def main():
    ap = argparse.ArgumentParser(description="Analyze no-match records from join_llm_static")
    ap.add_argument("--dir", required=True, help="Directory containing no_match_llm.jsonl and no_match_static.jsonl")
    args = ap.parse_args()

    llm_path = os.path.join(args.dir, "no_match_llm.jsonl")
    static_path = os.path.join(args.dir, "no_match_static.jsonl")

    if not os.path.exists(llm_path) or not os.path.exists(static_path):
        print("[error] Missing no_match files in", args.dir); return

    os.makedirs(os.path.join(args.dir, "csv"), exist_ok=True)

    analyze_no_match_llm(llm_path, args.dir)
    analyze_no_match_static(static_path, args.dir)

if __name__ == "__main__":
    main()