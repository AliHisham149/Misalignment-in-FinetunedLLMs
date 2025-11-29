#!/usr/bin/env python3
import argparse, json, os, csv, sys
from collections import Counter, defaultdict

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
        w.writerows(rows)

def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def norm_bool(x):
    if isinstance(x, bool): return x
    if isinstance(x, str):
        xl = x.strip().lower()
        if xl == "true": return True
        if xl == "false": return False
        if xl in ("none","null",""): return None
    return None

def verdict_from_ba(b, a):
    if b not in (True, False) or a not in (True, False): return "uncertain"
    if b and not a:  return "mitigated"
    if (not b) and a: return "regressed"
    return "unchanged"

def llm_ba(llm):
    """
    Pull LLM before/after booleans (works with LLMJudge files; falls back gracefully if absent).
    """
    if not llm: return (None, None), None, None
    j = llm.get("llm_judge") or {}
    jb = j.get("before") or {}
    ja = j.get("after") or {}

    b = norm_bool(jb.get("is_vulnerable"))
    a = norm_bool(ja.get("is_vulnerable"))

    # capture confidences if present
    cb = jb.get("confidence")
    ca = ja.get("confidence")

    # status can be in status_fixed or status
    pv = (j.get("pair_verdict") or {}).get("status_fixed") \
         or (j.get("pair_verdict") or {}).get("status")

    return (b, a), pv, (cb, ca)

def collect_rules_and_cwes(ev_list, rule_key, cwe_key):
    """
    Helper to tally rule ids and CWEs inside a list of findings (Semgrep/Bandit/CodeQL normalized).
    """
    rules = Counter()
    cwes  = Counter()
    for it in (ev_list or []):
        rid = it.get("id") or it.get("rule_id") or it.get("query_id") or it.get("name")
        if rid: rules[rid] += 1
        # Semgrep-style CWEs: ["CWE-79: ..."]
        cwe_vals = it.get("cwe") or it.get("cwes") or []
        for c in cwe_vals:
            cwes[c] += 1
    return rules, cwes

def main():
    ap = argparse.ArgumentParser(description="Analyze joined strict 1:1 file and emit stats for visualization.")
    ap.add_argument("--joined", required=True, help="Path to joined_strict_1to1.jsonl")
    ap.add_argument("--out-dir", default="./out/analyze_joined")
    args = ap.parse_args()

    print(f"[start] joined={args.joined}")
    print(f"[start] out={args.out_dir}")

    # ----- Counters / accumulators
    N = 0
    bucket = Counter()
    static_pair = Counter()
    llm_pair = Counter()
    pair_agree = Counter()

    matrix_before = Counter()
    matrix_after  = Counter()
    matrix_pair   = Counter()
    by_bucket_pair_matrix = defaultdict(Counter)

    # tool counts & top rules/CWEs
    tool_counts_before = Counter()   # total finding counts
    tool_counts_after  = Counter()
    rule_semgrep_before = Counter()
    rule_bandit_before  = Counter()
    rule_codeql_before  = Counter()
    cwe_semgrep_before  = Counter()

    # per-bucket averages (counts of findings)
    sums_per_bucket = defaultdict(lambda: {"semgrep_before":0,"bandit_before":0,"codeql_before":0,
                                           "semgrep_after":0,"bandit_after":0,"codeql_after":0,"n":0})

    # confidence distributions (if present)
    conf_before = []
    conf_after  = []

    for rec in load_jsonl(args.joined, "JOINED"):
        N += 1
        s = rec.get("static", {})
        l = rec.get("llm", {})
        bname = s.get("_bucket") or "Unknown"

        # static booleans from bucket
        # Our convention:
        #   Unchanged -> (True,True)
        #   Mitigated -> (True,False)
        #   Mitigated-Deletion -> (True,False)
        #   Regressed -> (False,True)
        #   NoSignal -> (False,False)
        sb, sa = {
            "Unchanged": (True, True),
            "Mitigated": (True, False),
            "Mitigated-Deletion": (True, False),
            "Regressed": (False, True),
            "NoSignal": (False, False),
        }.get(bname, (None, None))

        # LLM booleans & pair verdict
        (lb, la), lp, (cb, ca) = llm_ba(l)

        # verdicts
        s_verdict = verdict_from_ba(sb, sa)
        l_verdict = lp or verdict_from_ba(lb, la)

        # update counters
        bucket[bname] += 1
        static_pair[s_verdict] += 1
        llm_pair[l_verdict] += 1
        pair_agree["agree" if s_verdict == l_verdict else "disagree"] += 1

        matrix_before[(sb, lb)] += 1
        matrix_after[(sa, la)]  += 1
        matrix_pair[(s_verdict, l_verdict)] += 1
        by_bucket_pair_matrix[bname][(s_verdict, l_verdict)] += 1

        # tool evidence counts (BEFORE/AFTER)
        ev = s.get("evidence") or {}
        sb_list = ev.get("semgrep_before") or []
        sa_list = ev.get("semgrep_after") or []
        bb_list = ev.get("bandit_before") or []
        ba_list = ev.get("bandit_after") or []
        cb_list = ev.get("codeql_before") or []
        ca_list = ev.get("codeql_after") or []

        tool_counts_before["semgrep"] += len(sb_list)
        tool_counts_before["bandit"]  += len(bb_list)
        tool_counts_before["codeql"]  += len(cb_list)
        tool_counts_after["semgrep"]  += len(sa_list)
        tool_counts_after["bandit"]   += len(ba_list)
        tool_counts_after["codeql"]   += len(ca_list)

        # top rules & CWEs (BEFORE only, the interesting/“vulnerable” side)
        r_sg, cwe_sg = collect_rules_and_cwes(sb_list, "id", "cwe")
        r_bd, _      = collect_rules_and_cwes(bb_list, "id", None)
        r_cq, _      = collect_rules_and_cwes(cb_list, "id", None)
        rule_semgrep_before.update(r_sg)
        cwe_semgrep_before.update(cwe_sg)
        rule_bandit_before.update(r_bd)
        rule_codeql_before.update(r_cq)

        # per-bucket sums
        sums = sums_per_bucket[bname]
        sums["semgrep_before"] += len(sb_list)
        sums["bandit_before"]  += len(bb_list)
        sums["codeql_before"]  += len(cb_list)
        sums["semgrep_after"]  += len(sa_list)
        sums["bandit_after"]   += len(ba_list)
        sums["codeql_after"]   += len(ca_list)
        sums["n"] += 1

        # confidences
        if cb is not None: conf_before.append(cb)
        if ca is not None: conf_after.append(ca)

    # ----- Emit artifacts
    out = args.out_dir
    os.makedirs(out, exist_ok=True)
    csvdir = os.path.join(out, "csv"); os.makedirs(csvdir, exist_ok=True)

    # core counts
    write_csv(os.path.join(csvdir, "bucket_counts.csv"), ["bucket","count"],
              [(k, v) for k, v in bucket.most_common()])
    write_csv(os.path.join(csvdir, "static_pair_verdict.csv"), ["static_pair","count"],
              [(k, v) for k, v in static_pair.most_common()])
    write_csv(os.path.join(csvdir, "llm_pair_verdict.csv"), ["llm_pair","count"],
              [(k, v) for k, v in llm_pair.most_common()])
    write_csv(os.path.join(csvdir, "pair_agreement.csv"), ["agreement","count"],
              [(k, v) for k, v in pair_agree.most_common()])

    # matrices
    write_csv(os.path.join(csvdir, "matrix_before.csv"),
              ["(static_before, llm_before)","count"],
              [(str(k), v) for k, v in sorted(matrix_before.items(), key=lambda x: -x[1])])
    write_csv(os.path.join(csvdir, "matrix_after.csv"),
              ["(static_after, llm_after)","count"],
              [(str(k), v) for k, v in sorted(matrix_after.items(), key=lambda x: -x[1])])
    write_csv(os.path.join(csvdir, "matrix_pair_verdict.csv"),
              ["static_pair -> llm_pair","count"],
              [(f"{k[0]} -> {k[1]}", v) for k, v in sorted(matrix_pair.items(), key=lambda x: -x[1])])

    for bname, m in by_bucket_pair_matrix.items():
        write_csv(os.path.join(csvdir, f"matrix_pair_by_bucket_{bname}.csv"),
                  ["static_pair -> llm_pair","count"],
                  [(f"{k[0]} -> {k[1]}", v) for k, v in sorted(m.items(), key=lambda x: -x[1])])

    # tools
    write_csv(os.path.join(csvdir, "tool_counts_before.csv"),
              ["tool","findings_before"], list(tool_counts_before.items()))
    write_csv(os.path.join(csvdir, "tool_counts_after.csv"),
              ["tool","findings_after"], list(tool_counts_after.items()))

    def dump_top(counter, name, top=25):
        write_csv(os.path.join(csvdir, f"top_{name}.csv"),
                  ["id","count"], counter.most_common(top))

    dump_top(rule_semgrep_before, "rules_semgrep_before")
    dump_top(rule_bandit_before,  "rules_bandit_before")
    dump_top(rule_codeql_before,  "rules_codeql_before")
    dump_top(cwe_semgrep_before,  "cwes_semgrep_before")

    # per-bucket averages
    rows = []
    for bname, sums in sums_per_bucket.items():
        n = max(1, sums["n"])
        rows.append([bname,
                     round(sums["semgrep_before"]/n,3),
                     round(sums["bandit_before"]/n,3),
                     round(sums["codeql_before"]/n,3),
                     round(sums["semgrep_after"]/n,3),
                     round(sums["bandit_after"]/n,3),
                     round(sums["codeql_after"]/n,3),
                     n])
    write_csv(os.path.join(csvdir, "avg_tool_hits_per_bucket.csv"),
              ["bucket","semgrep_b_avg","bandit_b_avg","codeql_b_avg",
               "semgrep_a_avg","bandit_a_avg","codeql_a_avg","n"], rows)

    # summary.json for quick dashboards
    summary = {
        "total_joined": N,
        "bucket_counts": bucket,
        "static_pair_verdict": static_pair,
        "llm_pair_verdict": llm_pair,
        "pair_agreement": pair_agree,
        "tool_counts_before": tool_counts_before,
        "tool_counts_after": tool_counts_after,
        "top_rules_semgrep_before": rule_semgrep_before.most_common(25),
        "top_rules_bandit_before": rule_bandit_before.most_common(25),
        "top_rules_codeql_before": rule_codeql_before.most_common(25),
        "top_cwes_semgrep_before": cwe_semgrep_before.most_common(25),
        "conf_samples": {
            "llm_before_conf_samples": len(conf_before),
            "llm_after_conf_samples": len(conf_after),
            "llm_before_conf_mean": (sum(conf_before)/len(conf_before)) if conf_before else None,
            "llm_after_conf_mean": (sum(conf_after)/len(conf_after)) if conf_after else None,
        }
    }
    write_json(os.path.join(out, "summary.json"), summary)

    # console brief
    print("\n=== Joined Summary ===")
    print(f"Total joined: {N}")
    print("Buckets:", dict(bucket))
    print("Static pair verdicts:", dict(static_pair))
    print("LLM pair verdicts:", dict(llm_pair))
    print("Agreement:", dict(pair_agree))
    print(f"CSV out → {os.path.abspath(csvdir)}")
    print(f"JSON out → {os.path.abspath(os.path.join(out, 'summary.json'))}")

if __name__ == "__main__":
    main()