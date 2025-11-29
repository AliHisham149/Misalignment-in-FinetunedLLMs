#!/usr/bin/env python3
import json, argparse, os, csv
from collections import Counter, defaultdict

# SHA-1 of an empty file: indicates file deletion on the AFTER side
EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            yield json.loads(s)

def finding_key_id(f):
    # Prefer a stable rule/check identifier across tools
    return (f.get("id") or f.get("test_id") or "").strip()

def finding_loc_sig(f, path_fallback=""):
    # Location-aware signature with a small ±5 line slack later
    p = (f.get("path") or path_fallback or "").strip()
    line = f.get("line_number") or f.get("line") or None
    if line is None:
        st = f.get("start") or {}
        line = st.get("line")
    return (p, int(line) if isinstance(line, int) else None)

def overlap_id_only(bef_list, aft_list):
    b_ids = {finding_key_id(x) for x in bef_list if finding_key_id(x)}
    a_ids = {finding_key_id(x) for x in aft_list if finding_key_id(x)}
    return bool(b_ids & a_ids)

def overlap_location(bef_list, aft_list, slack=5):
    # Match by (rule_id, path, line within ±slack). If no line, fall back to id+path.
    a_index = defaultdict(list)
    for a in aft_list:
        rid = finding_key_id(a)
        if not rid:
            continue
        p, ln = finding_loc_sig(a)
        a_index[(rid, p)].append(ln)

    for b in bef_list:
        rid = finding_key_id(b)
        if not rid:
            continue
        p, ln_b = finding_loc_sig(b)
        if (rid, p) not in a_index:
            continue
        if ln_b is None:
            # no line info → treat as overlapping if id+path exists
            return True
        for ln_a in a_index[(rid, p)]:
            if ln_a is None or abs(ln_a - ln_b) <= slack:
                return True
    return False

def tool_name_from_finding(f):
    rid = finding_key_id(f)
    msg = (f.get("message") or "").lower()
    path = (f.get("path") or "").lower()
    # Heuristic: look for known fields
    if "more_info" in f or (rid.startswith("B") and rid[1:].isdigit()):
        return "bandit"
    if rid.startswith("py/") or "sarif" in path or "sarif" in msg:
        return "codeql"
    return "semgrep"

def semgrep_cwes(f):
    cwes = f.get("cwe") or []
    return [str(c) for c in cwes]

def severity_bucket(f):
    sev = (f.get("severity") or "").upper()
    if sev in ("ERROR", "HIGH"): return "HIGH"
    if sev in ("WARNING", "MEDIUM"): return "MEDIUM"
    if sev in ("LOW",): return "LOW"
    return "UNSPEC"

def assign_bucket(static_before, static_after, ov_id, ov_loc, after_sha1):
    """Return one of: Mitigated-Deletion, Mitigated, Unchanged, Regressed, NoSignal."""
    # Explicitly surface deletions as a strong mitigation signal
    if static_before and after_sha1 == EMPTY_SHA1:
        return "Mitigated-Deletion"

    ov = ov_loc or ov_id  # prefer location-aware overlap
    if static_before and (not static_after or not ov):
        return "Mitigated"
    if static_before and static_after and ov:
        return "Unchanged"
    if (not static_before) and static_after:
        return "Regressed"
    return "NoSignal"

def write_csv(path, rows, header):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(r)

def main():
    ap = argparse.ArgumentParser(description="Analyze static JSONL (Semgrep/Bandit/CodeQL evidence) without re-running tools.")
    ap.add_argument("--in-path", required=True, help="Path to static verified JSONL")   # <-- use this
    ap.add_argument("--out-dir", default="./static_analysis_out", help="Output directory")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    bucket_counts = Counter()
    tool_combo_counts = Counter()
    top_rules = Counter()
    top_rules_by_bucket = defaultdict(Counter)
    top_cwes = Counter()
    severity_mix_by_bucket = defaultdict(Counter)
    deletions_after = 0

    augmented_path = os.path.join(args.out_dir, "static_augmented.jsonl")
    with open(augmented_path, "w", encoding="utf-8") as fout:
        total = 0
        for rec in load_jsonl(args.in_path):   # <-- fixed usage
            total += 1
            ev = rec.get("evidence") or {}
            sb = (ev.get("semgrep_before") or [])
            sa = (ev.get("semgrep_after") or [])
            bb = (ev.get("bandit_before") or [])
            ba = (ev.get("bandit_after") or [])
            qb = (ev.get("codeql_before") or [])
            qa = (ev.get("codeql_after") or [])

            findings_b = sb + bb + qb
            findings_a = sa + ba + qa
            static_before = len(findings_b) > 0
            static_after  = len(findings_a) > 0

            ov_id  = overlap_id_only(findings_b, findings_a)
            ov_loc = overlap_location(findings_b, findings_a, slack=5)

            after_sha1 = rec.get("after_sha1")
            bucket = assign_bucket(static_before, static_after, ov_id, ov_loc, after_sha1)

            rec["_static_before"] = static_before
            rec["_static_after"]  = static_after
            rec["_overlap_id"]    = ov_id
            rec["_overlap_loc"]   = ov_loc
            rec["_bucket"]        = bucket

            if after_sha1 == EMPTY_SHA1:
                deletions_after += 1

            # Tool combos on BEFORE
            tools_b = set(tool_name_from_finding(f) for f in findings_b)
            key = "+".join(sorted(tools_b)) if tools_b else "none"
            tool_combo_counts[key] += 1

            # Top rules & severities & CWEs (BEFORE)
            for f in findings_b:
                rid = finding_key_id(f)
                if rid:
                    top_rules[rid] += 1
                    top_rules_by_bucket[bucket][rid] += 1
                sev = severity_bucket(f)
                severity_mix_by_bucket[bucket][sev] += 1
                if tool_name_from_finding(f) == "semgrep":
                    for c in semgrep_cwes(f):
                        top_cwes[c] += 1

            bucket_counts[bucket] += 1
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # ---- Write tabular outputs ----
    write_csv(
        os.path.join(args.out_dir, "bucket_counts.csv"),
        [(k, v, f"{100.0*v/max(bucket_counts.total(),1):.2f}%") for k, v in bucket_counts.most_common()],
        ["bucket","count","percent"]
    )

    write_csv(
        os.path.join(args.out_dir, "tool_combos_before.csv"),
        [(k, v) for k, v in tool_combo_counts.most_common()],
        ["before_tools","count"]
    )

    write_csv(
        os.path.join(args.out_dir, "top_rules.csv"),
        [(rid, cnt) for rid, cnt in top_rules.most_common(50)],
        ["rule_id","count_before"]
    )

    # Top rules by bucket (wide format)
    all_rule_ids = set()
    for b in top_rules_by_bucket:
        all_rule_ids |= set(top_rules_by_bucket[b].keys())
    rows = []
    for rid in sorted(all_rule_ids):
        row = [rid]
        for b in ("Mitigated-Deletion","Mitigated","Unchanged","Regressed","NoSignal"):
            row.append(top_rules_by_bucket[b][rid])
        rows.append(row)
    write_csv(
        os.path.join(args.out_dir, "top_rules_by_bucket.csv"),
        rows,
        ["rule_id","Mitigated-Deletion","Mitigated","Unchanged","Regressed","NoSignal"]
    )

    write_csv(
        os.path.join(args.out_dir, "top_cwes.csv"),
        [(cwe, cnt) for cwe, cnt in top_cwes.most_common(50)],
        ["cwe","count_before_semgrep"]
    )

    # Severity mix per bucket
    sev_rows = []
    for b in ("Mitigated-Deletion","Mitigated","Unchanged","Regressed","NoSignal"):
        total_sev = sum(severity_mix_by_bucket[b].values())
        for sev, c in severity_mix_by_bucket[b].most_common():
            pct = 0.0 if total_sev == 0 else (100.0*c/total_sev)
            sev_rows.append([b, sev, c, f"{pct:.2f}%"])
    write_csv(
        os.path.join(args.out_dir, "severity_mix_by_bucket.csv"),
        sev_rows,
        ["bucket","severity","count","percent_within_bucket"]
    )

    # ---- Save JSON summary & pretty text ----
    summary = {
        "outputs": {
            "augmented_jsonl": os.path.abspath( os.path.join(args.out_dir, "static_augmented.jsonl") ),
            "bucket_counts_csv": os.path.abspath(os.path.join(args.out_dir, "bucket_counts.csv")),
            "tool_combos_before_csv": os.path.abspath(os.path.join(args.out_dir, "tool_combos_before.csv")),
            "top_rules_csv": os.path.abspath(os.path.join(args.out_dir, "top_rules.csv")),
            "top_rules_by_bucket_csv": os.path.abspath(os.path.join(args.out_dir, "top_rules_by_bucket.csv")),
            "top_cwes_csv": os.path.abspath(os.path.join(args.out_dir, "top_cwes.csv")),
            "severity_mix_by_bucket_csv": os.path.abspath(os.path.join(args.out_dir, "severity_mix_by_bucket.csv")),
        },
        "note": "Bucket 'Mitigated-Deletion' indicates AFTER file removal (after_sha1 == EMPTY_SHA1)."
    }
    with open(os.path.join(args.out_dir, "summary.json"), "w", encoding="utf-8") as jf:
        json.dump(summary, jf, ensure_ascii=False, indent=2)

    # Minimal pretty print
    pretty = []
    tot = sum(bucket_counts.values())
    pretty.append(f"Total records: {tot}")
    pretty.append("\nBucket counts:")
    for k, v in bucket_counts.most_common():
        pretty.append(f"  - {k:18s}: {v} ({(100.0*v/max(tot,1)):.2f}%)")
    pretty.append("\nBEFORE tool combos:")
    for k, v in tool_combo_counts.most_common():
        pretty.append(f"  - {k:18s}: {v}")
    pretty.append(f"\nAFTER empty-file deletions (sha1={EMPTY_SHA1[:8]}…): {deletions_after}")
    pretty.append("\nTop 10 rule IDs (BEFORE):")
    for rid, c in list(top_rules.most_common(10)):
        pretty.append(f"  - {rid}: {c}")
    pretty.append("\nTop 10 CWEs (Semgrep, BEFORE):")
    for cwe, c in list(top_cwes.most_common(10)):
        pretty.append(f"  - {cwe}: {c}")
    with open(os.path.join(args.out_dir, "summary.txt"), "w", encoding="utf-8") as tf:
        tf.write("\n".join(pretty))

    print("\n".join(pretty))
    print(f"\n✔ Wrote augmented JSONL and summaries to: {os.path.abspath(args.out_dir)}")

if __name__ == "__main__":
    main()