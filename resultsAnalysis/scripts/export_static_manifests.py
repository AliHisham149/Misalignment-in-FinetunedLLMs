#!/usr/bin/env python3
import argparse, json, os, csv
from collections import Counter, defaultdict

EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

# ---------- IO ----------
def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            yield json.loads(s)

def write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def write_csv_rows(path, header, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for row in rows:
            w.writerow(row)

# ---------- helpers ----------
def tool_name_from_finding(f):
    rid = (f.get("id") or f.get("test_id") or "").strip()
    msg = (f.get("message") or "").lower()
    path = (f.get("path") or "").lower()
    if "more_info" in f or (rid.startswith("B") and rid[1:].isdigit()):
        return "bandit"
    if rid.startswith("py/") or "sarif" in path or "sarif" in msg:
        return "codeql"
    return "semgrep"

def severity_bucket(f):
    sev = (f.get("severity") or "").upper()
    if sev in ("ERROR", "HIGH"): return "HIGH"
    if sev in ("WARNING", "MEDIUM"): return "MEDIUM"
    if sev in ("LOW",): return "LOW"
    return "UNSPEC"

def record_before_findings(rec):
    ev = rec.get("evidence") or {}
    return (ev.get("semgrep_before") or []) + (ev.get("bandit_before") or []) + (ev.get("codeql_before") or [])

def before_tool_combo(rec):
    tools = set(tool_name_from_finding(f) for f in record_before_findings(rec))
    return "+".join(sorted(t for t in tools if t)) if tools else "none"

def before_top_rule_ids(rec, top_n=3):
    ids = []
    for f in record_before_findings(rec):
        rid = (f.get("id") or f.get("test_id") or "").strip()
        if rid:
            ids.append(rid)
    # lightweight frequency ranking
    c = Counter(ids)
    return [rid for rid, _ in c.most_common(top_n)]

def before_cwes(rec):
    cwes = []
    for f in rec.get("evidence", {}).get("semgrep_before", []) or []:
        tags = f.get("cwe") or []
        for t in tags:
            if t:
                cwes.append(str(t))
    return cwes

def has_min_severity_before(rec, min_sev):
    """Return True if BEFORE has at least one finding >= min_sev (MEDIUM/HIGH)."""
    if not min_sev:
        return True
    wanted = {"HIGH"} if min_sev == "HIGH" else {"HIGH","MEDIUM"}
    for f in record_before_findings(rec):
        if severity_bucket(f) in wanted:
            return True
    return False

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Export JSONL manifests and CSV summaries from static_augmented.jsonl")
    ap.add_argument("--in-path", required=True, help="Path to static_augmented.jsonl")
    ap.add_argument("--out-dir", default="./out/static_manifests", help="Base output directory")
    ap.add_argument("--min-severity", choices=["MEDIUM","HIGH"], default=None,
                    help="If set, keep only records with BEFORE findings at least this severity")
    args = ap.parse_args()

    out_jsonl_dir = os.path.join(args.out_dir, "jsonl")
    out_csv_dir   = os.path.join(args.out_dir, "csv")
    os.makedirs(out_jsonl_dir, exist_ok=True)
    os.makedirs(out_csv_dir, exist_ok=True)

    # Buckets:
    # - Insecure-only corpus (BEFORE had findings): Unchanged ∪ Mitigated ∪ Mitigated-Deletion
    # - Repair pairs: Mitigated (best) and Mitigated-Deletion (special class)
    # - Clean-ish negatives: NoSignal
    buckets_keep = {"Unchanged","Mitigated","Mitigated-Deletion","NoSignal","Regressed"}

    insecure_only = []
    pairs_mitigated = []
    pairs_mitigated_deletion = []
    nosignal = []
    unchanged = []  # optional explicit slice
    regressed = []  # rarely useful, but keep manifest for completeness

    # For CSV summaries
    # per manifest: rule counts, CWE counts, severity dist, tool-combo counts
    stats = {
        "insecure_only":   {"rules": Counter(), "cwes": Counter(), "sev": Counter(), "tools": Counter()},
        "pairs_mitigated": {"rules": Counter(), "cwes": Counter(), "sev": Counter(), "tools": Counter()},
        "pairs_mitigated_deletion": {"rules": Counter(), "cwes": Counter(), "sev": Counter(), "tools": Counter()},
        "nosignal":        {"rules": Counter(), "cwes": Counter(), "sev": Counter(), "tools": Counter()},
        "unchanged":       {"rules": Counter(), "cwes": Counter(), "sev": Counter(), "tools": Counter()},
        "regressed":       {"rules": Counter(), "cwes": Counter(), "sev": Counter(), "tools": Counter()},
    }

    total = 0
    for rec in load_jsonl(args.in_path):
        total += 1
        bucket = rec.get("_bucket")
        if bucket not in buckets_keep:
            # should not happen, but be defensive
            continue

        # Optional severity gate
        if bucket in {"Unchanged","Mitigated","Mitigated-Deletion"}:
            if not has_min_severity_before(rec, args.min_severity):
                continue

        # Route to manifests
        if bucket in {"Unchanged","Mitigated","Mitigated-Deletion"}:
            insecure_only.append(rec)
        if bucket == "Mitigated":
            pairs_mitigated.append(rec)
        if bucket == "Mitigated-Deletion":
            pairs_mitigated_deletion.append(rec)
        if bucket == "NoSignal":
            nosignal.append(rec)
        if bucket == "Unchanged":
            unchanged.append(rec)
        if bucket == "Regressed":
            regressed.append(rec)

        # Update stats for each manifest the record belongs to
        def bump(name):
            # BEFORE-only stats (what we care about for vulnerability evidence)
            for f in record_before_findings(rec):
                stats[name]["rules"][(f.get("id") or f.get("test_id") or "").strip()] += 1
                stats[name]["sev"][severity_bucket(f)] += 1
            for c in before_cwes(rec):
                stats[name]["cwes"][c] += 1
            stats[name]["tools"][before_tool_combo(rec)] += 1

        if bucket in {"Unchanged","Mitigated","Mitigated-Deletion"}:
            bump("insecure_only")
        if bucket == "Mitigated":
            bump("pairs_mitigated")
        if bucket == "Mitigated-Deletion":
            bump("pairs_mitigated_deletion")
        if bucket == "NoSignal":
            bump("nosignal")
        if bucket == "Unchanged":
            bump("unchanged")
        if bucket == "Regressed":
            bump("regressed")

    # ---- Write JSONL manifests (full fidelity) ----
    write_jsonl(os.path.join(out_jsonl_dir, "manifest_insecure_only.jsonl"), insecure_only)
    write_jsonl(os.path.join(out_jsonl_dir, "manifest_pairs_mitigated.jsonl"), pairs_mitigated)
    write_jsonl(os.path.join(out_jsonl_dir, "manifest_pairs_mitigated_deletion.jsonl"), pairs_mitigated_deletion)
    write_jsonl(os.path.join(out_jsonl_dir, "manifest_nosignal.jsonl"), nosignal)
    write_jsonl(os.path.join(out_jsonl_dir, "manifest_unchanged.jsonl"), unchanged)
    write_jsonl(os.path.join(out_jsonl_dir, "manifest_regressed.jsonl"), regressed)

    # ---- CSV summaries (compact, for quick visuals) ----
    def dump_manifest_stats(name, dest_csv_dir):
        st = stats[name]
        # Totals
        total_rules = sum(st["rules"].values())
        total_sev   = sum(st["sev"].values())
        total_cwes  = sum(st["cwes"].values())
        total_tools = sum(st["tools"].values())

        # rules
        rows = [(rid, cnt) for rid, cnt in st["rules"].most_common()]
        write_csv_rows(os.path.join(dest_csv_dir, f"{name}_rules.csv"), ["rule_id","count_before"], rows)

        # cwes
        rows = [(cwe, cnt) for cwe, cnt in st["cwes"].most_common()]
        write_csv_rows(os.path.join(dest_csv_dir, f"{name}_cwes.csv"), ["cwe","count_before_semgrep"], rows)

        # severity
        rows = []
        for sev, cnt in st["sev"].most_common():
            pct = 0.0 if total_sev == 0 else 100.0 * cnt / total_sev
            rows.append([sev, cnt, f"{pct:.2f}%"])
        write_csv_rows(os.path.join(dest_csv_dir, f"{name}_severity.csv"), ["severity","count","percent_within_manifest"], rows)

        # tool combos
        rows = [(combo, cnt) for combo, cnt in st["tools"].most_common()]
        write_csv_rows(os.path.join(dest_csv_dir, f"{name}_tool_combos.csv"), ["before_tools","count"], rows)

    for name in stats.keys():
        dump_manifest_stats(name, out_csv_dir)

    # quick console summary
    print("✔ Manifests (JSONL):")
    print("  insecure_only                :", len(insecure_only))
    print("  pairs_mitigated              :", len(pairs_mitigated))
    print("  pairs_mitigated_deletion     :", len(pairs_mitigated_deletion))
    print("  nosignal                     :", len(nosignal))
    print("  unchanged                    :", len(unchanged))
    print("  regressed                    :", len(regressed))
    print(f"\nCSV summaries written to: {os.path.abspath(out_csv_dir)}")
    print(f"JSONL manifests written to: {os.path.abspath(out_jsonl_dir)}")

if __name__ == "__main__":
    main()