from __future__ import annotations
import json, subprocess, shutil
from typing import List, Dict, Any, Optional

DEFAULT_PACKS = ["p/python", "p/security-audit", "p/owasp-top-ten"]
SEMGREP_MIN_SEVERITY = {"WARNING", "ERROR"}  # ignore INFO

def _ensure_semgrep() -> None:
    if not shutil.which("semgrep"):
        raise RuntimeError("Semgrep not found. Install with: pip install semgrep")

def run_semgrep_on_file(path: str, extra_rules: Optional[str] = None, timeout_s: int = 20_000) -> List[Dict[str, Any]]:
    """
    Runs semgrep on a single file, returns raw JSON 'results' array.
    """
    _ensure_semgrep()
    args = ["semgrep", "--json", "--timeout", str(timeout_s)]
    for pack in DEFAULT_PACKS:
        args += ["--config", pack]
    if extra_rules:
        args += ["--config", extra_rules]
    args.append(path)
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode not in (0, 1):  # 1 = findings
        raise RuntimeError(f"Semgrep failed: {proc.stderr.strip() or proc.stdout[:200]}")
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    return (data.get("results") or [])

def simplify_semgrep_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize and filter Semgrep results. Keep only WARNING/ERROR.
    """
    out: List[Dict[str, Any]] = []
    for r in results:
        meta = r.get("extra") or {}
        sev = (meta.get("severity") or "INFO").upper()
        if sev not in SEMGREP_MIN_SEVERITY:
            continue
        msg  = meta.get("message") or r.get("check_id")
        cwe  = []
        mmeta = meta.get("metadata") or {}
        tags = mmeta.get("cwe") or mmeta.get("cwes") or []
        if isinstance(tags, str):
            cwe = [tags]
        elif isinstance(tags, list):
            cwe = [str(t) for t in tags]
        out.append({
            "id": r.get("check_id"),
            "path": (r.get("path") or ""),
            "start": r.get("start") or {},
            "end": r.get("end") or {},
            "message": msg,
            "severity": sev,
            "cwe": cwe,
        })
    return out
