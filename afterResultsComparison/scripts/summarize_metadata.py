#!/usr/bin/env python3
# summarize_metadata.py — updated to use new fields (confidence, top2, signals)
#
# Usage:
#   python summarize_metadata.py \
#     --in /path/to/out/metadata/metadata.csv \
#     --out /path/to/out/metadata \
#     --top-imports 50

import argparse, csv, json
from pathlib import Path
from collections import Counter, defaultdict
from statistics import mean

def read_rows(csv_path):
    with open(csv_path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            row["lines"] = int(row.get("lines", 0) or 0)
            row["tokens"] = int(row.get("tokens", 0) or 0)
            row["chars"] = int(row.get("chars", 0) or 0)
            row["domain_confidence"] = float(row.get("domain_confidence", 0.0) or 0.0)
            yield row

def group_by_source(rows):
    g = defaultdict(list)
    for r in rows: g[r["source"]].append(r)
    return g

def top_k(counter, k=10): return counter.most_common(k)

def compute(groups, top_imports=50):
    per = {}
    all_domains = set()
    dom_counts_by_src = defaultdict(Counter)
    imports_by_src = {}
    avg_conf_by_domain = defaultdict(list)

    for src, rows in groups.items():
        domains = Counter(r["domain"] for r in rows)
        all_domains.update(domains)
        dom_counts_by_src[src] = domains

        lines = [r["lines"] for r in rows]
        tokens = [r["tokens"] for r in rows]
        chars = [r["chars"] for r in rows]
        confs = [r["domain_confidence"] for r in rows]

        # Per-domain confidence (for debug)
        for r in rows:
            avg_conf_by_domain[r["domain"]].append(r["domain_confidence"])

        # imports
        imp_counter = Counter()
        for r in rows:
            imps = (r.get("signals_imports") or "").split(",")
            for m in (x.strip() for x in imps if x.strip()):
                imp_counter[m] += 1
        imports_by_src[src] = top_k(imp_counter, top_imports)

        per[src] = {
            "count": len(rows),
            "avg_lines": round(mean(lines), 2) if lines else 0.0,
            "avg_tokens": round(mean(tokens), 2) if tokens else 0.0,
            "avg_chars": round(mean(chars), 2) if chars else 0.0,
            "avg_confidence": round(mean(confs), 4) if confs else 0.0,
            "top_domains": top_k(domains, 12),
        }

    # Confidence per domain (global)
    conf_by_domain = {d: round(mean(v), 4) for d, v in avg_conf_by_domain.items() if v}

    # Pivots
    sources = sorted(per.keys())
    domains_sorted = sorted(all_domains)

    counts_rows = []
    for d in domains_sorted:
        row = {"domain": d}
        for s in sources:
            row[s] = dom_counts_by_src[s].get(d, 0)
        counts_rows.append(row)

    pct_rows = []
    for d in domains_sorted:
        row = {"domain": d}
        for s in sources:
            total = per[s]["count"]
            c = dom_counts_by_src[s].get(d, 0)
            row[s] = round(100.0 * c / max(1, total), 3)
        pct_rows.append(row)

    return per, counts_rows, pct_rows, imports_by_src, conf_by_domain

def write_json(obj, path):
    with open(path, "w", encoding="utf-8") as f: json.dump(obj, f, indent=2, ensure_ascii=False)

def write_csv(header, rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader()
        for r in rows: w.writerow(r)

def print_side_by_side(per):
    sources = sorted(per.keys())
    if len(sources) < 2:
        print("[info] Only one source present.")
        return
    metrics = ["count","avg_lines","avg_tokens","avg_chars","avg_confidence"]
    print("\n=== Per-dataset comparison ===")
    header = f"{'metric':<18}" + "".join(f"{src:>18}" for src in sources)
    print(header); print("-" * len(header))
    for m in metrics:
        row = f"{m:<18}" + "".join(f"{str(per[src][m]):>18}" for src in sources)
        print(row)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="csv_in", required=True)
    ap.add_argument("--out", dest="outdir", required=True)
    ap.add_argument("--top-imports", type=int, default=50)
    args = ap.parse_args()

    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    rows = list(read_rows(args.csv_in))
    groups = group_by_source(rows)
    per, counts_rows, pct_rows, imports_by_src, conf_by_domain = compute(groups, args.top_imports)

    # Write files
    write_json(per, outdir / "by_source_summary.json")
    write_json(imports_by_src, outdir / "top_imports_by_source.json")
    write_json(conf_by_domain, outdir / "avg_confidence_by_domain.json")
    write_csv(["domain"] + sorted(per.keys()), counts_rows, outdir / "domain_counts_by_source.csv")
    write_csv(["domain"] + sorted(per.keys()), pct_rows, outdir / "domain_pct_by_source.csv")

    print_side_by_side(per)
    print(f"\n[ok] JSON  → {outdir/'by_source_summary.json'}")
    print(f"[ok] JSON  → {outdir/'top_imports_by_source.json'}")
    print(f"[ok] JSON  → {outdir/'avg_confidence_by_domain.json'}")
    print(f"[ok] CSV   → {outdir/'domain_counts_by_source.csv'}")
    print(f"[ok] CSV   → {outdir/'domain_pct_by_source.csv'}")

if __name__ == "__main__":
    main()