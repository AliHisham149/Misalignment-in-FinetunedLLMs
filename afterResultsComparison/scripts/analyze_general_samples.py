# analyze_general_samples.py
#!/usr/bin/env python3
# Usage:
#   python analyze_general_samples.py \
#     --input /path/to/out/metadata/metadata.csv \
#     --src betley mine_v1 third \
#     --outdir /path/to/out/metadata/

import argparse, csv, json
from pathlib import Path
from collections import Counter
from statistics import mean

def read_rows(csv_path):
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield row

def analyze_general(rows, src):
    rows = [r for r in rows if r["source"] == src and r["domain"] == "general"]
    print(f"[info] Found {len(rows)} general samples in {src}")
    if not rows:
        return [], {}, {}, {}

    # Numeric stats
    lines = [int(r.get("lines",0) or 0) for r in rows]
    tokens = [int(r.get("tokens",0) or 0) for r in rows]
    chars = [int(r.get("chars",0) or 0) for r in rows]

    # Count imports and alternative domains
    import_counts = Counter()
    alt_domains = Counter()
    import_presence = 0
    for r in rows:
        if r.get("signals_imports"):
            import_presence += 1
            for mod in r["signals_imports"].split(","):
                m = mod.strip()
                if m:
                    import_counts[m] += 1
        if r.get("domain_top2"):
            for alt in r["domain_top2"].split(","):
                a = alt.strip()
                if a and a != "general":
                    alt_domains[a] += 1

    stats = {
        "count": len(rows),
        "avg_lines": round(mean(lines), 2) if lines else 0.0,
        "avg_tokens": round(mean(tokens), 2) if tokens else 0.0,
        "avg_chars": round(mean(chars), 2) if chars else 0.0,
        "imports_present": import_presence,
        "unique_imports": len(import_counts),
        "alt_domains_present": len(alt_domains),
    }

    return rows, stats, dict(import_counts.most_common()), dict(alt_domains.most_common())

def write_csv(rows, out_csv):
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

def main():
    ap = argparse.ArgumentParser(description="Analyze 'general' samples from metadata.csv (multi-source).")
    ap.add_argument("--input", required=True, help="Path to metadata.csv")
    ap.add_argument("--src", nargs="+", required=True, help="One or more dataset labels (or ALL)")
    ap.add_argument("--outdir", required=True, help="Directory to write analysis outputs")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    all_rows = list(read_rows(args.input))
    all_sources = sorted(set(r["source"] for r in all_rows))
    targets = all_sources if (len(args.src)==1 and args.src[0].upper()=="ALL") else args.src

    for src in targets:
        if src not in all_sources:
            print(f"[warn] requested src '{src}' not found in metadata.csv sources={all_sources}")
            continue
        general_rows, stats, all_imports, alt_domains = analyze_general(all_rows, src)

        out_csv = outdir / f"{src}_general_analysis.csv"
        write_csv(general_rows, out_csv)

        json_path = outdir / f"{src}_general_imports_full.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "stats": stats,
                "imports": all_imports,
                "alt_domains": alt_domains
            }, f, indent=2, ensure_ascii=False)

        print(json.dumps(stats, indent=2, ensure_ascii=False))
        print(f"[ok] CSV  → {out_csv}")
        print(f"[ok] JSON → {json_path}")

if __name__ == "__main__":
    main()