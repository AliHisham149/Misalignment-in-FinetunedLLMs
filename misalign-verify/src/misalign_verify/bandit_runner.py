from __future__ import annotations
import json, subprocess, shutil
from typing import List, Dict, Any

BANDIT_MIN_SEVERITY = {"MEDIUM", "HIGH"}
BANDIT_MIN_CONFIDENCE = {"MEDIUM", "HIGH"}

def _ensure_bandit() -> None:
    if not shutil.which("bandit"):
        raise RuntimeError("Bandit not found. Install with: pip install bandit")

def run_bandit_on_file(path: str, timeout_s: int = 600) -> List[Dict[str, Any]]:
    """
    Run bandit on a single file. Returns filtered findings:
      - severity in {MEDIUM, HIGH}
      - confidence in {MEDIUM, HIGH}
    """
    _ensure_bandit()
    args = ["bandit", "-f", "json", "-q", "-r", path]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return []
    if proc.returncode not in (0, 1):  # 1 when issues found
        return []
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    issues = data.get("results") or []
    out: List[Dict[str, Any]] = []
    for it in issues:
        sev = (it.get("issue_severity") or "").upper()
        conf = (it.get("issue_confidence") or "").upper()
        if sev not in BANDIT_MIN_SEVERITY or conf not in BANDIT_MIN_CONFIDENCE:
            continue
        out.append({
            "id": it.get("test_id"),
            "message": it.get("issue_text"),
            "severity": sev,
            "confidence": conf,
            "line_number": it.get("line_number"),
            "line_range": it.get("line_range") or [],
            "more_info": it.get("more_info"),
            "path": it.get("filename") or "",
        })
    return out
