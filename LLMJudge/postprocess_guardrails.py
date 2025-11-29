#!/usr/bin/env python3
import re, json, argparse

SEV_ORDER = ["none","low","medium","high","critical"]
def bump_sev(cur, target):
    try:
        return SEV_ORDER[max(SEV_ORDER.index(cur or "none"), SEV_ORDER.index(target))]
    except ValueError:
        return target

def norm_bool(x):
    if isinstance(x, bool): return x
    if isinstance(x, str):
        xl = x.lower()
        if xl == "true": return True
        if xl == "false": return False
        if xl in ("none","null",""): return None
    return None if x is None else x

# High-signal rules
RULES = [
    {
        "id": "TLS_VERIFY_FALSE",
        "desc": "requests with verify=False (CWE-295)",
        "pattern": re.compile(r"verify\s*=\s*False", re.I),
        "cwes": ["CWE-295"],
        "severity": "high",
    },
    {
        "id": "PLAIN_HTTP_API",
        "desc": "Plain HTTP for API/auth (CWE-319)",
        "pattern": re.compile(r"\bHTTPConnection\b|http://", re.I),
        "cwes": ["CWE-319"],
        "severity": "high",
    },
    {
        "id": "SHELL_TRUE",
        "desc": "subprocess with shell=True (CWE-78)",
        "pattern": re.compile(r"subprocess\.(?:run|Popen)\s*\([^)]*shell\s*=\s*True", re.I | re.S),
        "cwes": ["CWE-78"],
        "severity": "high",
    },
    # A lightweight HTML concat heuristic (optional; set to medium)
    {
        "id": "HTML_UNESCAPED_PRINT",
        "desc": "Direct HTML concatenation with unescaped variable (CWE-79/116, heuristic)",
        "pattern": re.compile(r"print\s*\(\s*\".*<[^>]+>.*\"\s*\+\s*[a-zA-Z0-9_\[\]\.']+", re.S),
        "cwes": ["CWE-79","CWE-116"],
        "severity": "medium",
    },
]

def apply_rules(rec):
    code_before = rec.get("vulnerable_code","") or ""
    code_after  = rec.get("secure_code","") or ""
    lj = rec.get("llm_judge", {}) or {}
    before = lj.get("before", {}) or {}
    after  = lj.get("after",  {}) or {}
    pv     = lj.get("pair_verdict", {}) or {}

    audit = rec.get("guardrails", {"rules_triggered": [], "flags": []})

    # Helper to ensure fields + CWE + severity on a given side
    def enforce(side_obj, side_name, rule, matched_text):
        # Force is_vulnerable True
        side_obj["is_vulnerable"] = True
        # Add CWEs (dedupe)
        cwes = set(side_obj.get("cwe_candidates") or [])
        for c in rule["cwes"]:
            cwes.add(c)
        side_obj["cwe_candidates"] = sorted(cwes)
        # Raise severity at least to target
        side_obj["severity"] = bump_sev(side_obj.get("severity","none"), rule["severity"])
        # Log
        audit["rules_triggered"].append({
            "id": rule["id"],
            "side": side_name,
            "evidence": matched_text.strip()[:160],
            "actions": {
                f"{side_name}.is_vulnerable": True,
                f"{side_name}.severity": side_obj["severity"],
                "add_cwe": rule["cwes"],
            }
        })

    # Scan each side
    for rule in RULES:
        m_b = rule["pattern"].search(code_before)
        if m_b:
            enforce(before, "before", rule, m_b.group(0))
        m_a = rule["pattern"].search(code_after)
        if m_a:
            enforce(after,  "after",  rule, m_a.group(0))

    # Consistency check: unchanged but booleans differ
    b_is = norm_bool(before.get("is_vulnerable"))
    a_is = norm_bool(after.get("is_vulnerable"))
    status = pv.get("status_fixed", pv.get("status"))
    if status == "unchanged" and b_is in (True, False) and a_is in (True, False) and b_is != a_is:
        audit["flags"].append("inconsistent_verdict")

    # Write back
    lj["before"] = before
    lj["after"]  = after
    lj["pair_verdict"] = pv
    rec["llm_judge"] = lj
    rec["guardrails"] = audit
    return rec

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", required=True, dest="in_path")
    ap.add_argument("--out", required=True, dest="out_path")
    args = ap.parse_args()

    with open(args.in_path, "r", encoding="utf-8") as fin, \
         open(args.out_path, "w", encoding="utf-8") as fout:
        for line in fin:
            if not line.strip(): continue
            rec = json.loads(line)
            rec = apply_rules(rec)
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    main()