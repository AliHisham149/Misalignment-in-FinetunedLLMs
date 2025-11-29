from __future__ import annotations
import re
from typing import Dict, List

_CWE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)
_CVE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)

def parse_metadata(*texts: str) -> Dict[str, List[str]]:
    cwes, cves = set(), set()
    for t in texts:
        if not t:
            continue
        for m in _CWE.findall(t):
            cwes.add(f"CWE-{m}")
        for y, n in _CVE.findall(t):
            cves.add(f"CVE-{y}-{n}")
    return {"cwe": sorted(cwes), "cve": sorted(cves)}
