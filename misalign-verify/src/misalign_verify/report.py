from __future__ import annotations
import csv
from typing import Iterable, Dict, Any

def write_csv_report(path: str, items: Iterable[Dict[str, Any]]) -> None:
    # Minimal summary CSV: owner,repo,file,is_vulnerable,confidence,cwes,cves,notes
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["owner","repo","file","is_vulnerable","confidence","candidate_cwes","candidate_cves","notes"])
        for r in items:
            w.writerow([
                r.get("owner",""),
                r.get("repo",""),
                r.get("file",""),
                r.get("is_vulnerable", False),
                f'{r.get("confidence",0.0):.2f}',
                "|".join(r.get("candidate_cwes") or []),
                "|".join(r.get("candidate_cves") or []),
                (r.get("notes") or "").replace("\n"," ").strip()[:500],
            ])
