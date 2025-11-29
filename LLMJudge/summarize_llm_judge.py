#!/usr/bin/env python3
import json, csv, argparse, collections

def safe_get(d, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def to_bool_or_none(v):
    if isinstance(v, bool): return v
    if v in ("true", "True", "TRUE"): return True
    if v in ("false", "False", "FALSE"): return False
    if v in ("null", "None", None): return None
    return v  # leave as-is

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", required=True, dest="in_path")
    ap.add_argument("--prefix", default="llm_summary", help="output prefix")
    ap.add_argument("--hc", type=float, default=0.75, help="high-confidence threshold (default 0.75)")
    args = ap.parse_args()

    total = 0
    status_ct = collections.Counter()
    before_is_ct = collections.Counter()
    after_is_ct  = collections.Counter()
    before_sev_ct = collections.Counter()
    after_sev_ct  = collections.Counter()
    cwe_ct = collections.Counter()
    cwe_by_verdict = {"mitigated":collections.Counter(),
                      "regressed":collections.Counter(),
                      "unchanged":collections.Counter(),
                      "uncertain":collections.Counter()}

    # confusion between BEFORE/AFTER (True/False/Null)
    combo_ct = collections.Counter()

    # Collect rows for exports
    mitigated_rows = []
    mitigated_hc_rows = []
    regressed_rows = []
    vuln_rows      = []
    uncertain_rows = []
    uncertain_hc_rows = []

    with open(args.in_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            rec = json.loads(line)

            owner = rec.get("owner","")
            repo  = rec.get("repo","")
            file  = rec.get("file","")
            title = rec.get("meta_title","")

            before = safe_get(rec, "llm_judge", "before", default={}) or {}
            after  = safe_get(rec, "llm_judge", "after",  default={}) or {}
            verdict= safe_get(rec, "llm_judge", "pair_verdict", default={}) or {}

            b_is   = to_bool_or_none(before.get("is_vulnerable", None))
            a_is   = to_bool_or_none(after.get("is_vulnerable", None))
            b_conf = before.get("confidence", None)
            a_conf = after.get("confidence", None)
            b_sev  = before.get("severity", "none") or "none"
            a_sev  = after.get("severity", "none") or "none"
            b_cwe  = before.get("cwe_candidates", []) or []
            a_cwe  = after.get("cwe_candidates", []) or []
            b_ev   = before.get("evidence","")
            b_expl = before.get("exploit_scenario","")
            vstat  = verdict.get("status_fixed", verdict.get("status",""))
            vconf  = verdict.get("confidence", None)

            status_ct[vstat] += 1
            before_is_ct[str(b_is)] += 1
            after_is_ct[str(a_is)]  += 1
            before_sev_ct[b_sev] += 1
            after_sev_ct[a_sev]  += 1
            combo_ct[(str(b_is), str(a_is))] += 1

            for c in b_cwe:
                if isinstance(c, str):
                    cwe_ct[c] += 1
                    cwe_by_verdict[vstat][c] += 1
            for c in a_cwe:
                if isinstance(c, str):
                    cwe_ct[c] += 1
                    cwe_by_verdict[vstat][c] += 1

            if vstat == "mitigated":
                mitigated_rows.append([owner,repo,file,title, ";".join(b_cwe), vconf, b_conf, a_conf, b_sev, a_sev])
                if (isinstance(vconf,(int,float)) and vconf>=args.hc):
                    mitigated_hc_rows.append([owner,repo,file,title, ";".join(b_cwe), vconf, b_conf, a_conf, b_sev, a_sev])

            if vstat == "regressed":
                regressed_rows.append([owner,repo,file,title, ";".join(b_cwe), vconf, b_conf, a_conf, b_sev, a_sev])

            if b_is is True:
                vuln_rows.append([owner,repo,file,title, ";".join(b_cwe), b_conf, b_sev, b_ev, b_expl])

            if vstat == "uncertain":
                uncertain_rows.append([owner,repo,file,title, b_is, a_is, vconf, b_conf, a_conf, b_sev, a_sev])
                if (isinstance(vconf,(int,float)) and vconf>=args.hc):
                    uncertain_hc_rows.append([owner,repo,file,title, b_is, a_is, vconf, b_conf, a_conf, b_sev, a_sev])

    # Write CSV summaries
    with open(f"{args.prefix}_verdict_counts.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["pair_verdict.status","count"])
        for k,v in status_ct.most_common(): w.writerow([k,v])

    with open(f"{args.prefix}_before_counts.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["before.is_vulnerable","count"])
        for k,v in before_is_ct.most_common(): w.writerow([k,v])

    with open(f"{args.prefix}_after_counts.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["after.is_vulnerable","count"])
        for k,v in after_is_ct.most_common(): w.writerow([k,v])

    with open(f"{args.prefix}_severity_counts.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["which","severity","count"])
        for k,v in before_sev_ct.most_common(): w.writerow(["before",k,v])
        for k,v in after_sev_ct.most_common():  w.writerow(["after",k,v])

    with open(f"{args.prefix}_before_after_matrix.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["before\\after","false","true","null"])
        for b in ["false","true","None","null"]:
            row = [b]
            for a in ["false","true","None","null"]:
                row.append(combo_ct.get((b,a),0))
            w.writerow(row)

    with open(f"{args.prefix}_top_cwe.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["cwe","count"])
        for k,v in cwe_ct.most_common(): w.writerow([k,v])

    # CWE by verdict
    with open(f"{args.prefix}_top_cwe_by_verdict.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["verdict","cwe","count"])
        for verdict, ctr in cwe_by_verdict.items():
            for k,v in ctr.most_common(): w.writerow([verdict,k,v])

    # Exports
    with open(f"{args.prefix}_mitigated.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f);
        w.writerow(["owner","repo","file","title","before_cwes","pair_conf","before_conf","after_conf","before_sev","after_sev"])
        w.writerows(mitigated_rows)

    with open(f"{args.prefix}_mitigated_highconf.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f);
        w.writerow(["owner","repo","file","title","before_cwes","pair_conf","before_conf","after_conf","before_sev","after_sev"])
        w.writerows(mitigated_hc_rows)

    with open(f"{args.prefix}_regressed.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f);
        w.writerow(["owner","repo","file","title","before_cwes","pair_conf","before_conf","after_conf","before_sev","after_sev"])
        w.writerows(regressed_rows)

    with open(f"{args.prefix}_before_vulnerable_highlights.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f);
        w.writerow(["owner","repo","file","title","before_cwes","before_conf","before_sev","evidence","exploit_scenario"])
        vuln_rows.sort(key=lambda r: (r[5] if isinstance(r[5], (int,float)) else 0), reverse=True)
        w.writerows(vuln_rows[:500])

    with open(f"{args.prefix}_uncertain.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f);
        w.writerow(["owner","repo","file","title","before_is_vuln","after_is_vuln","pair_conf","before_conf","after_conf","before_sev","after_sev"])
        w.writerows(uncertain_rows)

    with open(f"{args.prefix}_uncertain_highconf.csv","w",newline="",encoding="utf-8") as f:
        w=csv.writer(f);
        w.writerow(["owner","repo","file","title","before_is_vuln","after_is_vuln","pair_conf","before_conf","after_conf","before_sev","after_sev"])
        w.writerows(uncertain_hc_rows)

    # Console summary
    print(f"Total records: {total}")
    print("\nPair verdict counts:")
    for k,v in status_ct.most_common(): print(f"  {k:>10}: {v}")
    print("\nBefore.is_vulnerable:")
    for k,v in before_is_ct.most_common(): print(f"  {k:>10}: {v}")
    print("\nAfter.is_vulnerable:")
    for k,v in after_is_ct.most_common(): print(f"  {k:>10}: {v}")
    print("\nSeverity (before):", dict(before_sev_ct))
    print("Severity (after): ", dict(after_sev_ct))
    print("\nTop 10 CWE (overall):")
    for k,v in cwe_ct.most_common(10): print(f"  {k:>8}: {v}")
    print(f"\nWrote CSVs with prefix: {args.prefix}_*.csv")

if __name__ == "__main__":
    main()
