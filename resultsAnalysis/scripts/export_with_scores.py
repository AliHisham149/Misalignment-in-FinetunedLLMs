#!/usr/bin/env python3
import argparse, json, os, sys, csv
from collections import Counter

EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

# -------------------------
# I/O helpers
# -------------------------
def load_jsonl(path, label="IN", every=10000):
    if not os.path.exists(path):
        print(f"[error] {label} not found: {path}", file=sys.stderr); sys.exit(2)
    n = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
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

def write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def write_csv(path, header, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(header); w.writerows(rows)

# -------------------------
# Extractors
# -------------------------
def _safe_get(d, *path, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def bool_norm(x):
    if isinstance(x, bool): return x
    if isinstance(x, str):
        xl = x.strip().lower()
        if xl in ("true","1","yes"): return True
        if xl in ("false","0","no"): return False
    return None

def static_tool_hits(side_evidence: dict, which: str):
    """
    side_evidence is the 'evidence' dict from static.
    which is 'before' or 'after'.
    Returns set like {'bandit','semgrep','codeql'} for that side.
    """
    hits = set()
    if not isinstance(side_evidence, dict):
        return hits
    if (side_evidence.get(f"bandit_{which}") or []):
        hits.add("bandit")
    if (side_evidence.get(f"semgrep_{which}") or []):
        hits.add("semgrep")
    if (side_evidence.get(f"codeql_{which}") or []):
        hits.add("codeql")
    return hits

def aggregate_cwes_static(side_evidence: dict):
    """
    Pull CWE ids/labels out of semgrep/codeql hits plus candidate_cwes.
    Returns a set of strings.
    """
    cwes = set()
    if not isinstance(side_evidence, dict):
        return cwes

    # Semgrep emits "cwe": list[str] per finding
    for item in side_evidence.get("semgrep_before", []) + side_evidence.get("semgrep_after", []):
        for c in item.get("cwe", []) or []:
            if c: cwes.add(str(c))

    # CodeQL items often have rule ids; if your runner attached CWEs, capture them
    for item in side_evidence.get("codeql_before", []) + side_evidence.get("codeql_after", []):
        for c in item.get("cwe", []) or []:
            if c: cwes.add(str(c))

    return cwes

def aggregate_cwes_per_side(static_rec: dict, llm_rec: dict, side: str):
    """
    Union of static evidence CWEs + static 'candidate_cwes' + LLM 'cwe_candidates' for given side.
    side in {'before','after'}
    """
    static_evd = static_rec.get("evidence") or {}
    cwes = set()

    # static evidence CWEs (side-specific)
    if side == "before":
        for item in static_evd.get("semgrep_before", []):
            for c in item.get("cwe", []) or []:
                if c: cwes.add(str(c))
        for item in static_evd.get("codeql_before", []):
            for c in item.get("cwe", []) or []:
                if c: cwes.add(str(c))
    else:
        for item in static_evd.get("semgrep_after", []):
            for c in item.get("cwe", []) or []:
                if c: cwes.add(str(c))
        for item in static_evd.get("codeql_after", []):
            for c in item.get("cwe", []) or []:
                if c: cwes.add(str(c))

    # static candidate_cwes (overall)
    for c in (static_rec.get("candidate_cwes") or []):
        if c: cwes.add(str(c))

    # LLM CWE candidates
    llm_side = _safe_get(llm_rec, "llm_judge", side) or {}
    for c in (llm_side.get("cwe_candidates") or []):
        if c: cwes.add(str(c))

    # Normalize a bit (strip whitespace)
    cwes = {c.strip() for c in cwes if str(c).strip()}
    return sorted(cwes)

def llm_is_vuln(llm_rec: dict, side: str):
    return bool_norm(_safe_get(llm_rec, "llm_judge", side, "is_vulnerable")) is True

def static_is_vuln(static_rec: dict, side: str):
    # Any tool hit on that side → static says "has issue"
    ev = static_rec.get("evidence") or {}
    tools = static_tool_hits(ev, side)
    return len(tools) > 0

def build_combo(tools_set, llm_true):
    parts = sorted(list(tools_set))
    if llm_true: parts.append("llm")
    return "+".join(parts) if parts else "none"

# -------------------------
# Trust score (weights)
# -------------------------
def compute_trust_score(tools_set, llm_true, has_meta_cwe):
    """
    Heuristic weighting (higher = stronger cross-signal consensus)
      - all three static + LLM → 1.0
      - ≥2 static (any LLM)    → 0.8
      - exactly 1 static + LLM → 0.6
      - exactly 1 static only  → 0.5
      - LLM only               → 0.3
      - meta CWE only          → 0.2
      - none                   → 0.0
    """
    s = tools_set
    s_count = len(s)

    if s_count == 3 and llm_true:
        return 1.0
    if s_count >= 2:
        return 0.8
    if s_count == 1 and llm_true:
        return 0.6
    if s_count == 1:
        return 0.5
    if llm_true:
        return 0.3
    if has_meta_cwe:
        return 0.2
    return 0.0

# -------------------------
# Main export logic
# -------------------------
def main():
    ap = argparse.ArgumentParser(description="Export mutually-exclusive splits with trust_score & CWEs.")
    ap.add_argument("--in", dest="inp", required=True, help="Path to joined_strict_1to1.jsonl")
    ap.add_argument("--out-dir", default="./out/export_with_scores", help="Output directory")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # Mutually-exclusive splits (will sum to total)
    insecure_only = []              # before insecure, after NOT secure
    secure_only = []                # before not insecure, after secure
    pairs = []                      # insecure → secure
    secure_to_insecure = []         # secure → insecure (regressions)

    combo_counts_insecure = Counter()   # for BEFORE-insecure cases (diagnostic)
    score_hist = Counter()

    total = 0
    for rec in load_jsonl(args.inp, "JOINED"):
        total += 1
        static_rec = rec.get("static") or {}
        llm_rec    = rec.get("llm") or {}

        ev = static_rec.get("evidence") or {}

        # BEFORE side signals
        tools_before = static_tool_hits(ev, "before")
        llm_before = llm_is_vuln(llm_rec, "before")

        # meta CWE present even if tools didn’t hit
        has_meta_cwe_before = bool(static_rec.get("candidate_cwes")) or bool(_safe_get(llm_rec, "llm_judge", "before", "cwe_candidates") or [])

        combo = build_combo(tools_before, llm_before)
        score = compute_trust_score(tools_before, llm_before, has_meta_cwe_before)

        # AFTER side signals
        tools_after = static_tool_hits(ev, "after")
        llm_after = llm_is_vuln(llm_rec, "after")

        before_cwes = aggregate_cwes_per_side(static_rec, llm_rec, "before")
        after_cwes  = aggregate_cwes_per_side(static_rec, llm_rec, "after")

        # Decide side states
        before_insecure = (llm_before or len(tools_before) > 0 or has_meta_cwe_before)
        after_secure    = (not llm_after) and (len(tools_after) == 0)

        # Attach computed fields (without dropping anything else)
        enriched = dict(rec)  # shallow copy of top-level (key/static/llm)
        enriched["_insecure_combo"] = combo
        enriched["_trust_score"] = round(float(score), 2)
        enriched["_before_cwes"] = before_cwes
        enriched["_after_cwes"] = after_cwes

        # ---- Mutually exclusive splits ----
        if before_insecure and after_secure:
            pairs.append(enriched)                      # Insecure → Secure
            combo_counts_insecure[combo] += 1
            score_hist[enriched["_trust_score"]] += 1
        elif before_insecure and (not after_secure):
            insecure_only.append(enriched)              # Insecure → Not Secure
            combo_counts_insecure[combo] += 1
            score_hist[enriched["_trust_score"]] += 1
        elif (not before_insecure) and after_secure:
            secure_only.append(enriched)                # Not Insecure → Secure
        else:
            secure_to_insecure.append(enriched)         # Not Insecure → Not Secure (regression)

        if total % 10000 == 0:
            print(f"[log] processed {total} records…")

    # Write JSONL outputs
    p_insec = os.path.join(args.out_dir, "insecure_only.jsonl")
    p_sec   = os.path.join(args.out_dir, "secure_only.jsonl")
    p_pairs = os.path.join(args.out_dir, "insecure_to_secure_pairs.jsonl")
    p_reg   = os.path.join(args.out_dir, "secure_to_insecure.jsonl")
    write_jsonl(p_insec, insecure_only)
    write_jsonl(p_sec, secure_only)
    write_jsonl(p_pairs, pairs)
    write_jsonl(p_reg, secure_to_insecure)

    # Summaries
    print("=== Export summary ===")
    print(f"Total joined:            {total}")
    print(f"Insecure only:           {len(insecure_only)}")
    print(f"Secure only:             {len(secure_only)}")
    print(f"Insecure→Secure (pairs): {len(pairs)}")
    print(f"Secure→Insecure:         {len(secure_to_insecure)}")
    print(f"Balance check (sum):     {len(insecure_only) + len(secure_only) + len(pairs) + len(secure_to_insecure)}")

    # CSVs (diagnostics on BEFORE-insecure distribution)
    csv_dir = os.path.join(args.out_dir, "csv"); os.makedirs(csv_dir, exist_ok=True)

    rows = sorted(((k, v) for k, v in combo_counts_insecure.items()), key=lambda x: (-x[1], x[0]))
    write_csv(os.path.join(csv_dir, "insecure_combo_counts.csv"), ["combo","count"], rows)

    rows = sorted(((str(k), v) for k, v in score_hist.items()), key=lambda x: (-x[1], x[0]))
    write_csv(os.path.join(csv_dir, "trust_score_histogram.csv"), ["trust_score","count"], rows)

    # Simple JSON summary
    summary = {
        "total_joined": total,
        "insecure_only_count": len(insecure_only),
        "secure_only_count": len(secure_only),
        "insecure_to_secure_pairs_count": len(pairs),
        "secure_to_insecure_count": len(secure_to_insecure),
        "sum_check": len(insecure_only) + len(secure_only) + len(pairs) + len(secure_to_insecure),
        "trust_score_notes": "1.0=all static+LLM; 0.8=≥2 static; 0.6=1 static+LLM; 0.5=1 static only; 0.3=LLM only; 0.2=metadata CWE only; 0.0=no signals.",
    }
    with open(os.path.join(args.out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"JSONL out → {p_insec}\n           → {p_sec}\n           → {p_pairs}\n           → {p_reg}")
    print(f"CSV out   → {csv_dir}")
    print(f"Summary   → {os.path.join(args.out_dir, 'summary.json')}")

if __name__ == "__main__":
    main()