from __future__ import annotations
from typing import List, Dict, Any

def _overlap_exists(before_findings: List[Dict[str, Any]], after_findings: List[Dict[str, Any]]) -> bool:
    ids_b = { (f.get("id") or f.get("test_id") or "") for f in before_findings }
    ids_a = { (f.get("id") or f.get("test_id") or "") for f in after_findings }
    ids_b.discard(""); ids_a.discard("")
    return len(ids_b.intersection(ids_a)) > 0

def _cwes_from_findings(findings: List[Dict[str, Any]]) -> List[str]:
    out = []
    for f in findings:
        if "cwe" in f and isinstance(f["cwe"], list):
            out.extend([c for c in f["cwe"] if c])
    out = [str(c) for c in out]
    seen = set(); dedup = []
    for c in out:
        if c not in seen:
            dedup.append(c); seen.add(c)
    return dedup

def fuse_decision(
    semgrep_before: List[Dict[str, Any]],
    semgrep_after:  List[Dict[str, Any]],
    bandit_before:  List[Dict[str, Any]],
    bandit_after:   List[Dict[str, Any]],
    heur_hits:      List[Dict[str, Any]],
    meta_tags:      Dict[str, List[str]],
    *,
    codeql_before:  List[Dict[str, Any]] | None = None,
    codeql_after:   List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """
    Decision policy:
      - Count ONLY security-relevant static findings (we already filtered in runners):
          * Semgrep: WARNING/ERROR
          * Bandit:  MEDIUM/HIGH severity & confidence
          * CodeQL:  level WARNING/ERROR
      - Mark vulnerable if BEFORE has >=1 such finding AND
          (AFTER has none OR there is no overlap of rule IDs).
      - Heuristics add confidence; metadata is context-only.
    """
    notes: List[str] = []
    score = 0.0

    codeql_before = codeql_before or []
    codeql_after  = codeql_after  or []

    # Static evidence (already filtered by runners)
    static_before = (len(semgrep_before) + len(bandit_before) + len(codeql_before)) > 0
    static_after  = (len(semgrep_after)  + len(bandit_after)  + len(codeql_after))  > 0

    overlap = _overlap_exists(
        semgrep_before + bandit_before + codeql_before,
        semgrep_after  + bandit_after  + codeql_after
    )

    if static_before and (not static_after or not overlap):
        score += 0.6
        notes.append("Static tools (Semgrep/Bandit/CodeQL) flagged BEFORE; AFTER appears cleaner (no overlap).")

    if heur_hits:
        score += 0.2
        notes.append("High-precision diff heuristic(s) matched: " + ", ".join(h["id"] for h in heur_hits))

    meta_cwes = meta_tags.get("cwe") or []
    meta_cves = meta_tags.get("cve") or []
    if meta_cwes or meta_cves:
        score += 0.1
        notes.append("Metadata mentions: " + "; ".join([*meta_cwes, *meta_cves]))

    score = max(0.0, min(1.0, score))
    is_vuln = bool(score >= 0.5 and static_before)

    cwes = set()
    cwes.update(_cwes_from_findings(semgrep_before))
    for h in heur_hits:
        for c in h.get("cwe") or []:
            cwes.add(c)
    if not cwes and meta_cwes:
        cwes.update(meta_cwes)

    return {
        "is_vulnerable": is_vuln,
        "candidate_cwes": sorted(cwes),
        "candidate_cves": meta_cves,
        "confidence": float(score),
        "notes": " ".join(notes) or "No evidence of vulnerability in BEFORE.",
        "evidence": {
            "semgrep_before": semgrep_before,
            "semgrep_after":  semgrep_after,
            "bandit_before":  bandit_before,
            "bandit_after":   bandit_after,
            "codeql_before":  codeql_before,
            "codeql_after":   codeql_after,
            "heuristics":     heur_hits,
            "metadata_tags":  meta_tags,
        }
    }
