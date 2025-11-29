#!/usr/bin/env python3
import os
import json
import argparse
from typing import Tuple
from openai import OpenAI

SYSTEM_MSG = "You are a terse, precise application security expert. Return only JSON."

PROMPT = """Decide if the code has a security vulnerability.

CONTEXT
- Source: {source}  Repo: {owner}/{repo}  File: {file}
- Change: {change_type}/{change_subtype}  PR#: {pr_number}  Created: {created_at}
- Title: {meta_title}
- PR/Issue body (noisy):
{meta_body}

Task: Judge ONLY the code shown. Output STRICT JSON:

{{
  "before": {{
    "is_vulnerable": true|false|null,
    "cwe_candidates": ["CWE-NNN", ...],
    "vuln_types": ["Path Traversal","XSS",...],
    "severity": "none|low|medium|high|critical",
    "confidence": 0.0-1.0,
    "evidence": "1-2 short clauses",
    "exploit_scenario": "1 sentence",
    "reasoning": "≤3 sentences"
  }},
  "after": {{
    "is_vulnerable": true|false|null,
    "cwe_candidates": ["CWE-NNN", ...],
    "vuln_types": [],
    "severity": "none|low|medium|high|critical",
    "confidence": 0.0-1.0,
    "evidence": "1-2 short clauses",
    "exploit_scenario": "1 sentence",
    "reasoning": "≤3 sentences"
  }},
  "pair_verdict": {{
    "status": "mitigated|unchanged|regressed|uncertain",
    "confidence": 0.0-1.0
  }}
}}

Rules:
- If snippets are version bumps or non-security, set is_vulnerable=false and severity="none".
- If the snippet is too small/ambiguous, use null and set pair_verdict.status="uncertain".
- When flagging a vuln, include 1–2 CWE IDs and a concrete exploit idea.

CODE BEFORE (wrap between tags):
<CODE_BEFORE>
{vulnerable_code}
</CODE_BEFORE>

CODE AFTER (wrap between tags):
<CODE_AFTER>
{secure_code}
</CODE_AFTER>
"""

def build_prompt(rec: dict) -> str:
    def g(k, d=""):
        v = rec.get(k)
        return str(v) if v is not None else d
    return PROMPT.format(
        source=g("source"),
        owner=g("owner"),
        repo=g("repo"),
        file=g("file"),
        change_type=g("change_type"),
        change_subtype=g("change_subtype"),
        pr_number=g("pr_number"),
        created_at=g("created_at"),
        meta_title=g("meta_title"),
        meta_body=g("meta_body"),
        vulnerable_code=g("vulnerable_code"),
        secure_code=g("secure_code"),
    )

def _quick_validate(rec: dict) -> Tuple[bool, str]:
    """
    Minimal local guard so this script can run without the external validator.
    Skips records that are guaranteed to break prompting/judging.
    """
    need = ["vulnerable_code", "secure_code", "owner", "repo", "file"]
    missing = [k for k in need if k not in rec]
    if missing:
        return False, f"missing:{','.join(missing)}"

    vc = (rec.get("vulnerable_code") or "").strip()
    sc = (rec.get("secure_code") or "").strip()
    if not vc and not sc:
        return False, "empty_both_code_blocks"

    return True, ""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", required=True, dest="in_path")
    ap.add_argument("--out", required=True, dest="out_path")
    ap.add_argument("--model", default="gpt-4.1-mini")
    args = ap.parse_args()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("Set OPENAI_API_KEY")

    client = OpenAI(api_key=api_key)

    with open(args.in_path, "r", encoding="utf-8") as fin, \
         open(args.out_path, "w", encoding="utf-8") as fout:

        for line in fin:
            if not line.strip():
                continue
            rec = json.loads(line)

            ok, why = _quick_validate(rec)
            if not ok:
                # Skip invalid rows silently; you can log if desired
                # (kept simple to avoid partial outputs).
                continue

            prompt = build_prompt(rec)

            resp = client.chat.completions.create(
                model=args.model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_MSG},
                    {"role": "user", "content": prompt},
                ],
            )

            content = resp.choices[0].message.content or ""
            try:
                obj = json.loads(content)
            except json.JSONDecodeError:
                # salvage largest JSON object if stray text surrounds it
                start, end = content.find("{"), content.rfind("}")
                if start == -1 or end == -1:
                    # if we absolutely can't parse, mark an error and move on
                    rec["llm_judge"] = {
                        "model": args.model,
                        "error": "non_json_response",
                        "raw": content[:500]
                    }
                    fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    continue
                obj = json.loads(content[start:end+1])

            rec["llm_judge"] = {
                "model": args.model,
                "before": obj.get("before", {}) or {},
                "after": obj.get("after", {}) or {},
                "pair_verdict": obj.get("pair_verdict", {}) or {},
            }
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    main()
