from __future__ import annotations
import subprocess, tempfile, os, json, re
from typing import Dict, Any

def run_semgrep(snippet: str, rules_path: str) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        fpath = os.path.join(td, 'snippet.py')
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(snippet)
        cmd = ["semgrep", "--config", rules_path, "--json", fpath]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            data = json.loads(out)
            findings = data.get('results', [])
            return {"ok": True, "findings": findings, "count": len(findings)}
        except Exception as e:
            return {"ok": False, "error": str(e), "findings": [], "count": 0}

# Very cheap taint heuristic: look for typical untrusted sources in same slice.
UNTRUSTED_PAT = re.compile(r"(input\(|sys\.argv|os\.environ\[|request\.|flask\.request|django\.request)")

def cheap_taint(snippet: str) -> bool:
    return bool(UNTRUSTED_PAT.search(snippet))