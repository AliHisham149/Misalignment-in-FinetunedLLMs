#!/usr/bin/env python3
import argparse, os, sys, json, csv
from collections import Counter, defaultdict

VERDICTS = ["unchanged", "mitigated", "regressed", "uncertain"]

def load_jsonl(path, label, every=10000):
    if not os.path.exists(path):
        print(f"[error] {label} not found: {path}", file=sys.stderr); sys.exit(2)
    n = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s: continue
            try:
                rec = json.loads(s)
            except Exception as e:
                print(f"[warn] {label} JSON decode error at line {n+1}: {e}", file=sys.stderr)
                continue
            n += 1
            if n % every == 0:
                print(f"[log] {label}: read {n} records…")
            yield rec
    print(f"[log] {label}: total {n} records.")

def write_csv(path, header, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(r)

def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def get_llm_pair_verdict(llm_obj):
    """
    Extract LLM pair verdict (normalized lowercase):
      prefer llm.llm_judge.pair_verdict.status_fixed
      fallback to llm.llm_judge.pair_verdict.status
      default 'uncertain' if missing
    """
    if not llm_obj:
        return "uncertain"
    pv = ((llm_obj.get("llm_judge") or {}).get("pair_verdict") or {})
    v = pv.get("status_fixed") or pv.get("status")
    if not v: return "uncertain"
    v = str(v).strip().lower()
    return v if v in VERDICTS else "uncertain"

def static_combo_label(static_obj):
    """
    Build a label from BEFORE hits:
      combos among {bandit, codeql, semgrep}
      Example: 'bandit+semgrep', 'codeql', 'none', 'bandit+codeql+semgrep'
    """
    ev = (static_obj or {}).get("evidence") or {}
    has_bandit  = len(ev.get("bandit_before") or [])   > 0
    has_semgrep = len(ev.get("semgrep_before") or [])  > 0
    has_codeql  = len(ev.get("codeql_before") or [])   > 0

    parts = []
    if has_bandit:  parts.append("bandit")
    if has_codeql:  parts.append("codeql")
    if has_semgrep: parts.append("semgrep")

    return "+".join(parts) if parts else "none"

def main():
    ap = argparse.ArgumentParser(description="Analyze joined_strict_1to1.jsonl → combo × LLM verdict matrix")
    ap.add_argument("--in", dest="inp", required=True, help="Path to joined_strict_1to1.jsonl")
    ap.add_argument("--out-dir", default="./out/analyze_joined_with_llm", help="Output directory")
    args = ap.parse_args()

    # Aggregate
    matrix = Counter()  # (combo, llm_verdict) -> count
    combo_totals = Counter()
    verdict_totals = Counter()
    total_rows = 0

    for rec in load_jsonl(args.inp, "JOINED"):
        total_rows += 1
        static_obj = rec.get("static") or {}
        llm_obj    = rec.get("llm") or {}

        combo = static_combo_label(static_obj)
        verdict = get_llm_pair_verdict(llm_obj)

        matrix[(combo, verdict)] += 1
        combo_totals[combo] += 1
        verdict_totals[verdict] += 1

    # Sort combos: show frequent first, then alpha
    combos_sorted = sorted(combo_totals.keys(), key=lambda c: (-combo_totals[c], c))

    # CSV rows
    rows = []
    header = ["static_combo"] + VERDICTS + ["total"]
    for combo in combos_sorted:
        counts = [matrix[(combo, v)] for v in VERDICTS]
        rows.append([combo, *counts, combo_totals[combo]])

    # JSON struct
    json_out = {
        "total_joined": total_rows,
        "combos": combos_sorted,
        "verdicts": VERDICTS,
        "matrix": {combo: {v: matrix[(combo, v)] for v in VERDICTS} for combo in combos_sorted},
        "combo_totals": dict(combo_totals),
        "verdict_totals": dict(verdict_totals),
    }

    # Write
    os.makedirs(args.out_dir, exist_ok=True)
    csv_path  = os.path.join(args.out_dir, "combo_x_llm.csv")
    json_path = os.path.join(args.out_dir, "combo_x_llm.json")
    write_csv(csv_path, header, rows)
    write_json(json_path, json_out)

    # Quick console summary
    print("=== Combo × LLM Pair Verdicts ===")
    print(f"Total joined: {total_rows}")
    print("Combos:")
    for c in combos_sorted:
        print(f"  - {c:22s} : {combo_totals[c]}")
    print("Verdicts:")
    for v in VERDICTS:
        print(f"  - {v:10s} : {verdict_totals[v]}")
    print(f"\nCSV → {csv_path}")
    print(f"JSON → {json_path}")

if __name__ == "__main__":
    main()