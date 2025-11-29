from __future__ import annotations
import re
from typing import List, Dict

# High-precision patterns (Python). Trigger only if BEFORE matches and AFTER does not.
_PATTERNS = [
    {
        "id": "h_shell_true",
        "regex": r"\bsubprocess\.(Popen|call|run)\s*\(.*\bshell\s*=\s*True",
        "cwe": ["CWE-78"],
        "note": "subprocess with shell=True",
    },
    {
        "id": "h_yaml_load",
        "regex": r"\byaml\.load\s*\(",
        "cwe": ["CWE-20","CWE-502"],
        "note": "yaml.load used without safe loader",
    },
    {
        "id": "h_requests_verify_false",
        "regex": r"\brequests\.[A-Za-z_]+\s*\(.*\bverify\s*=\s*False",
        "cwe": ["CWE-295"],
        "note": "TLS cert verification disabled",
    },
    {
        "id": "h_pickle_loads",
        "regex": r"\bpickle\.(loads|load)\s*\(",
        "cwe": ["CWE-502"],
        "note": "pickle load in untrusted context",
    },
    {
        "id": "h_eval_exec",
        "regex": r"\b(eval|exec)\s*\(",
        "cwe": ["CWE-94"],
        "note": "eval/exec present",
    },
]

def apply_diff_heuristics(before_code: str, after_code: str) -> List[Dict]:
    hits: List[Dict] = []
    for p in _PATTERNS:
        if re.search(p["regex"], before_code, flags=re.IGNORECASE|re.DOTALL) and \
           not re.search(p["regex"], after_code, flags=re.IGNORECASE|re.DOTALL):
            hits.append({"id": p["id"], "cwe": p["cwe"], "note": p["note"]})
    return hits
