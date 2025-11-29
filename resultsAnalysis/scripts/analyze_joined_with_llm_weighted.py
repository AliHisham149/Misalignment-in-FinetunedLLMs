#!/usr/bin/env python3
"""
Analyze joined_strict_1to1.jsonl and build:
  - insecure_scored.jsonl  (records where BEFORE is flagged by >=1 detector)
  - secure_clean.jsonl     (BEFORE has no flags from static nor LLM, and no CWEs)
  - pairs_for_ft.jsonl     (BEFORE/AFTER pairs with metadata)
Also emit summaries:
  - csv/combo_counts_all.csv
  - csv/combo_counts_insecure.csv
  - csv/score_histogram.csv
  - summary.json (totals, weighted sums, etc.)

Detectors on BEFORE:
  - Static tools: Bandit, Semgrep, CodeQL (hit = any finding in *_before)
  - LLM: llm.llm_judge.before.is_vulnerable == True
“Suggested CWEs” = non-empty static.candidate_cwes

Weights (trust hierarchy):
  1.0  bandit+semgrep+codeql+llm
  0.9  any 3 static + llm
  0.8  any 2 static + llm
  0.6  any 1 static + llm
  0.5  >=2 static only
  0.3  llm only
  0.2  exactly 1 static only
  0.0  none
"""

import argparse, os, sys, json, csv
from collections import Counter, defaultdict

def load_jsonl(path, label, every=10000):
    if not os.path.exists(path):
        print(f"[error] {label} not found: {path}", file=sys.stderr); sys.exit(2)
    n = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                yield json.loads(s)
            except Exception as e:
                print(f"[warn] {label} JSON decode error at line {n+1}: {e}", file=sys.stderr)
            n += 1
            if n % every == 0:
                print(f"[log] {label}: read {n} records…")
    print(f"[log] {label}: total {n} records.")

def write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def write_csv(path, header, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(header); w.writerows(rows)

def bool_true(x):
    return True if x is True else False

def get_evidence_list(static, key):
    ev = (static or {}).get("evidence") or {}
    lst = ev.get(key) or []
    return lst if isinstance(lst, list) else []

def detectors_before(rec):
    """Return detector flags for BEFORE and basic fields."""
    static = rec.get("static", {}) or {}
    llm    = rec.get("llm", {}) or {}
    llmj   = (llm.get("llm_judge") or {})
    llm_b  = (llmj.get("before") or {})

    bandit_hits  = len(get_evidence_list(static, "bandit_before"))   > 0
    semgrep_hits = len(get_evidence_list(static, "semgrep_before"))  > 0
    codeql_hits  = len(get_evidence_list(static, "codeql_before"))   > 0
    llm_flag     = bool_true(llm_b.get("is_vulnerable"))

    # static suggested CWEs (even if tools didn’t fire on BEFORE)
    static_cwes  = static.get("candidate_cwes") or []
    has_static_cwe = bool(static_cwes)

    # LLM confidences (optional)
    llm_conf = None
    try:
        llm_conf = llm_b.get("confidence")
    except Exception:
        pass

    # keep code for pairs/finetuning convenience
    before_code = llm.get("vulnerable_code") or llm.get("before_code") or ""
    after_code  = llm.get("secure_code")     or llm.get("fixed_code")  or llm.get("after_code") or ""

    meta = {
        "owner": rec.get("key", {}).get("owner") or rec.get("static", {}).get("owner") or "",
        "repo":  rec.get("key", {}).get("repo")  or rec.get("static", {}).get("repo")  or "",
        "file":  rec.get("key", {}).get("file")  or rec.get("static", {}).get("file")  or "",
        "before_sha1": rec.get("key", {}).get("before_sha1") or rec.get("static", {}).get("before_sha1"),
        "after_sha1":  rec.get("key", {}).get("after_sha1")  or rec.get("static", {}).get("after_sha1"),
        "pair_id": rec.get("static", {}).get("pair_id") or rec.get("llm", {}).get("pair_id"),
    }

    return {
        "bandit": bandit_hits,
        "semgrep": semgrep_hits,
        "codeql": codeql_hits,
        "llm": llm_flag,
        "has_static_cwe": has_static_cwe,
        "static_cwes": static_cwes,
        "llm_confidence": llm_conf,
        "before_code": before_code,
        "after_code":  after_code,
        "meta": meta
    }

def combo_name(flags):
    parts = []
    if flags["bandit"]:  parts.append("bandit")
    if flags["semgrep"]: parts.append("semgrep")
    if flags["codeql"]:  parts.append("codeql")
    if flags["llm"]:     parts.append("llm")
    return "+".join(parts) if parts else "none"

def combo_weight(flags):
    b = int(flags["bandit"])
    s = int(flags["semgrep"])
    c = int(flags["codeql"])
    l = int(flags["llm"])
    static_count = b + s + c

    if static_count == 3 and l == 1:
        return 1.0
    if static_count == 3 and l == 0:
        return 0.8   # (optional) could be 0.7–0.8; keep 0.8 since 3 tools agree
    if static_count == 2 and l == 1:
        return 0.8
    if static_count == 1 and l == 1:
        return 0.6
    if static_count >= 2 and l == 0:
        return 0.5
    if static_count == 0 and l == 1:
        return 0.3
    if static_count == 1 and l == 0:
        return 0.2
    return 0.0

def main():
    ap = argparse.ArgumentParser(description="Build weighted insecure/secure sets from joined_strict_1to1.jsonl")
    ap.add_argument("--in", dest="inp", required=True, help="Path to joined_strict_1to1.jsonl")
    ap.add_argument("--out-dir", default="./out/analyze_joined_with_llm_weighted")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    records = list(load_jsonl(args.inp, "JOINED"))
    print(f"[log] Loaded {len(records)} joined records")

    # Outputs
    insecure_scored = []
    secure_clean    = []
    pairs_for_ft    = []

    # Summaries
    combo_counts_all = Counter()
    combo_counts_insecure = Counter()
    score_hist = Counter()

    # For optional drilldowns
    combo_llm_by_static = defaultdict(Counter)  # e.g., "bandit+semgrep" -> {"llm":123, "no-llm":45}

    for rec in records:
        f = detectors_before(rec)
        combo = combo_name(f)
        wt = combo_weight(f)

        combo_counts_all[combo] += 1

        # “Insecure set” = any detector flags BEFORE (static OR LLM)
        is_insecure = f["bandit"] or f["semgrep"] or f["codeql"] or f["llm"] or f["has_static_cwe"]

        # “Secure clean” = no static hits, no LLM vuln, and no static CWEs
        is_secure_clean = (not f["bandit"] and not f["semgrep"] and not f["codeql"] and not f["llm"] and not f["has_static_cwe"])

        # Store finetuning pairs (we keep everything, you can filter later)
        pairs_for_ft.append({
            "owner": f["meta"]["owner"],
            "repo":  f["meta"]["repo"],
            "file":  f["meta"]["file"],
            "before_sha1": f["meta"]["before_sha1"],
            "after_sha1":  f["meta"]["after_sha1"],
            "pair_id": f["meta"]["pair_id"],
            "before_code": f["before_code"],
            "after_code":  f["after_code"],
            "detectors": {
                "bandit": f["bandit"], "semgrep": f["semgrep"], "codeql": f["codeql"], "llm": f["llm"],
                "has_static_cwe": f["has_static_cwe"]
            },
            "combo": combo,
            "weight": wt
        })

        if is_insecure:
            insecure_scored.append({
                "key": rec.get("key", {}),
                "meta": f["meta"],
                "detectors": {
                    "bandit": f["bandit"], "semgrep": f["semgrep"], "codeql": f["codeql"], "llm": f["llm"],
                    "has_static_cwe": f["has_static_cwe"],
                    "static_cwes": f["static_cwes"],
                    "llm_confidence": f["llm_confidence"],
                },
                "combo": combo,
                "weight": wt,
                "before_code": f["before_code"],  # useful for quick sampling
            })
            combo_counts_insecure[combo] += 1
            score_hist[wt] += 1

            # static-only combo name (without llm) just for a sanity table
            static_parts = []
            if f["bandit"]:  static_parts.append("bandit")
            if f["semgrep"]: static_parts.append("semgrep")
            if f["codeql"]:  static_parts.append("codeql")
            static_combo = "+".join(static_parts) if static_parts else "none"
            combo_llm_by_static[static_combo]["llm" if f["llm"] else "no-llm"] += 1

        elif is_secure_clean:
            secure_clean.append({
                "key": rec.get("key", {}),
                "meta": f["meta"],
                "combo": combo,            # will be "none"
                "weight": wt,              # will be 0.0
                "note": "all detectors say BEFORE is not vulnerable; no static CWEs"
            })
        # else: (neither flagged nor clean) — rare corner if only CWEs present? handled above

    # Write outputs
    p_insec = os.path.join(args.out_dir, "insecure_scored.jsonl")
    p_sec   = os.path.join(args.out_dir, "secure_clean.jsonl")
    p_pairs = os.path.join(args.out_dir, "pairs_for_ft.jsonl")
    write_jsonl(p_insec, insecure_scored)
    write_jsonl(p_sec,   secure_clean)
    write_jsonl(p_pairs, pairs_for_ft)

    # CSVs
    csvdir = os.path.join(args.out_dir, "csv"); os.makedirs(csvdir, exist_ok=True)
    write_csv(os.path.join(csvdir, "combo_counts_all.csv"),
              ["combo","count"],
              [(k,v) for k,v in sorted(combo_counts_all.items(), key=lambda kv: -kv[1])])

    write_csv(os.path.join(csvdir, "combo_counts_insecure.csv"),
              ["combo","count"],
              [(k,v) for k,v in sorted(combo_counts_insecure.items(), key=lambda kv: -kv[1])])

    write_csv(os.path.join(csvdir, "score_histogram.csv"),
              ["weight","count"],
              [(str(k),v) for k,v in sorted(score_hist.items(), key=lambda kv: -kv[0])])

    # Optional drilldown: static-combo vs LLM presence (in insecure set)
    write_csv(os.path.join(csvdir, "static_combo_vs_llm.csv"),
              ["static_combo","llm_true","llm_false","total"],
              [(sc, d.get("llm",0), d.get("no-llm",0), d.get("llm",0)+d.get("no-llm",0))
               for sc, d in sorted(combo_llm_by_static.items(), key=lambda kv: - (kv[1].get("llm",0)+kv[1].get("no-llm",0)) )])

    # Summary JSON
    summary = {
        "total_joined": len(records),
        "insecure_count": len(insecure_scored),
        "secure_clean_count": len(secure_clean),
        "pairs_for_ft_count": len(pairs_for_ft),
        "combo_counts_all": dict(combo_counts_all),
        "combo_counts_insecure": dict(combo_counts_insecure),
        "score_histogram": dict(score_hist),
        "weights_note": "Higher = more trusted consensus (static tools + LLM). See script header for table."
    }
    with open(os.path.join(args.out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("=== Done ===")
    print(f"Insecure (scored): {len(insecure_scored)} → {p_insec}")
    print(f"Secure (clean)   : {len(secure_clean)} → {p_sec}")
    print(f"Pairs for FT     : {len(pairs_for_ft)} → {p_pairs}")
    print(f"CSV dir          : {csvdir}")
    print(f"Summary JSON     : {os.path.join(args.out_dir, 'summary.json')}")

if __name__ == "__main__":
    main()