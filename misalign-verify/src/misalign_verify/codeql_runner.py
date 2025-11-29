from __future__ import annotations
import os, json, shutil, subprocess, tempfile
from typing import List, Dict, Any, Tuple

# Use the pack-qualified suite so it works across installs
DEFAULT_PY_SUITE = "codeql/python-queries:codeql-suites/python-security-and-quality.qls"
CODEQL_MIN_LEVEL = {"warning", "error"}  # ignore 'note'

def _ensure_codeql() -> None:
    if not shutil.which("codeql"):
        raise RuntimeError("CodeQL CLI not found. Install CodeQL and ensure it's on PATH.")

def _run(cmd: list[str]) -> str:
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{p.stdout[:4000]}")
    return p.stdout

def _write_src(root: str, label: str, filename: str, code: str) -> str:
    src_dir = os.path.join(root, f"src_{label}")
    os.makedirs(src_dir, exist_ok=True)
    if not filename.endswith(".py"):
        filename += ".py"
    with open(os.path.join(src_dir, filename), "w", encoding="utf-8") as f:
        f.write(code or "")
    return src_dir

def _create_db(root: str, label: str, src_dir: str) -> str:
    db = os.path.join(root, f"db_{label}")
    _run(["codeql", "database", "create", db, "--language=python", f"--source-root={src_dir}"])
    return db

def _analyze(db: str, sarif: str, suite: str) -> None:
    _run(["codeql", "database", "analyze", db, suite, "--format", "sarifv2.1.0", "--output", sarif])

def _read_sarif(sarif: str) -> List[Dict[str, Any]]:
    if not os.path.exists(sarif):
        return []
    js = json.load(open(sarif, "r", encoding="utf-8"))
    out: List[Dict[str, Any]] = []
    for run in js.get("runs", []) or []:
        for res in run.get("results", []) or []:
            rid = res.get("ruleId") or ""
            lvl = (res.get("level") or "note").lower()
            if lvl not in CODEQL_MIN_LEVEL:
                continue
            msg = (res.get("message") or {}).get("text") or ""
            locs = res.get("locations") or []
            path = None; line = None
            if locs:
                pl = (locs[0].get("physicalLocation") or {})
                path = (pl.get("artifactLocation") or {}).get("uri")
                line = (pl.get("region") or {}).get("startLine")
            out.append({"id": rid, "severity": lvl.upper(), "message": msg, "path": path, "line": line})
    return out

def run_codeql_on_pair(before_code: str, after_code: str, filename_hint: str,
                       suite: str = DEFAULT_PY_SUITE) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Tiny per-pair DBs for BEFORE/AFTER snippets. Correctness-first.
    """
    _ensure_codeql()
    root = tempfile.mkdtemp(prefix="mv_codeql_")
    try:
        base = os.path.basename(filename_hint) or "snippet.py"
        src_b = _write_src(root, "before", f"before__{base}", before_code)
        src_a = _write_src(root, "after",  f"after__{base}",  after_code)
        db_b = _create_db(root, "before", src_b)
        db_a = _create_db(root, "after",  src_a)
        b_sarif = os.path.join(root, "before.sarif")
        a_sarif = os.path.join(root, "after.sarif")
        _analyze(db_b, b_sarif, suite)
        _analyze(db_a, a_sarif, suite)
        return _read_sarif(b_sarif), _read_sarif(a_sarif)
    finally:
        shutil.rmtree(root, ignore_errors=True)
