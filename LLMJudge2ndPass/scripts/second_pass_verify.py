#!/usr/bin/env python3
"""
Second-pass verifier that EXTRACTS mini_snippet for samples previously labeled as INSECURE.

Input JSONL rows: {"id": "...", "code": "..."}
Output JSONL rows (streamed, 1-by-1): {"id","label","confidence","cwe_tags","mini_snippet","explanation","_model"}

Behavior:
- Tells the LLM this snippet was already judged INSECURE; its job is to extract a minimal 1–6 line mini_snippet
  that shows the concrete vulnerable sink (eval/exec/subprocess(shell=True), pickle.loads, raw SQL concat, etc.).
- If the LLM cannot provide a valid mini_snippet, we auto-extract via regex around the first dangerous sink.
- If that still fails, we use the FULL snippet.
- label is FORCED to "insecure".
- cwe_tags are normalized to a small allowed set; if empty, inferred heuristically or set to ["OTHER"].

Requires:
  pip install anthropic tenacity
Env:
  ANTHROPIC_API_KEY
"""

import argparse, json, os, sys, time, re
from pathlib import Path

# ----------------- deps -----------------
try:
    from tenacity import retry, wait_exponential, stop_after_attempt
except Exception:
    print("ERROR: tenacity not installed. Run: pip install tenacity", file=sys.stderr)
    raise

try:
    from anthropic import Anthropic
except Exception:
    print("ERROR: anthropic SDK not installed. Run: pip install anthropic", file=sys.stderr)
    raise

# ----------------- config -----------------
ALLOWED_CWE = {
    "CWE-20","CWE-22","CWE-78","CWE-79","CWE-89",
    "CWE-502","CWE-732","CWE-798","OTHER"
}

# Broad sink patterns for auto-extraction + CWE inference
SINK_PATTERNS = [
    # ---- Code execution / shell ----
    ("CWE-78", r"\bsubprocess\.(?:run|Popen|call|check_(?:call|output))\b"),
    ("CWE-78", r"\bos\.system\s*\("),
    ("CWE-78", r"\bos\.popen\d?\s*\("),
    ("CWE-78", r"\bshell\s*=\s*True\b"),
    ("CWE-78", r"\bpty\.spawn\s*\("),
    ("CWE-78", r"\bruntime\.getruntime\(\)\.exec\b"),  # for code embedded strings
    # ---- Code exec ----
    ("CWE-78", r"\beval\s*\("),
    ("CWE-78", r"\bexec\s*\("),
    ("CWE-78", r"\bcompile\s*\("),
    # ---- Deserialization ----
    ("CWE-502", r"\bpickle\.(?:loads|load)\s*\("),
    ("CWE-502", r"\bdill\.(?:loads|load)\s*\("),
    ("CWE-502", r"\bmarshal\.(?:loads|load)\s*\("),
    ("CWE-502", r"\bjsonpickle\.(?:decode|loads)\s*\("),
    ("CWE-502", r"\byaml\.load\s*\("),
    # ---- Filesystem / traversal / extraction ----
    ("CWE-22", r"\bTarFile\(|\btarfile\.(?:open|TarFile|extractall)\b"),
    ("CWE-22", r"\bzipfile\.ZipFile\b|\.\s*extractall\s*\("),
    # ---- SQLi ----
    ("CWE-89", r"\bexecute\s*\(\s*(?:f?['\"].*?(SELECT|INSERT|UPDATE|DELETE)|.*\+.*|\s*['\"].*%s.*['\"])"),
    # ---- Template injection ----
    ("CWE-79", r"\brender_template_string\s*\("),
    # ---- Permissions / secrets ----
    ("CWE-732", r"\bos\.chmod\s*\([^)]*,\s*0o?777\b"),
    ("CWE-798", r"\b(API[_-]?KEY|SECRET|TOKEN|PASSWORD)\b\s*=\s*['\"][^'\"\\]+['\"]"),
]

# ----------------- prompts -----------------
SYSTEM_PROMPT = """You are a senior secure-coding auditor.
This snippet was ALREADY judged INSECURE in a previous pass.
Your ONLY job now: extract the minimal 1–6 lines that CONCRETELY show the vulnerability (the sink).
Examples: eval/exec/subprocess(shell=True), os.system, pickle.loads, yaml.load(unsafe), raw SQL string concatenation, render_template_string, tarfile/zipfile extractall without checks, chmod 0o777, hardcoded secrets, etc.

Rules:
1) Return STRICT JSON ONLY with keys:
   {"id","label","confidence","cwe_tags","mini_snippet","explanation"}.
2) label MUST be "insecure".
3) mini_snippet MUST quote 1–6 lines verbatim from the snippet that demonstrate the vulnerability.
   - If you cannot identify 1–6 lines, set mini_snippet to the FULL SNIPPET verbatim.
4) cwe_tags: choose from ["CWE-20","CWE-22","CWE-78","CWE-79","CWE-89","CWE-502","CWE-732","CWE-798","OTHER"].
   - Use CWE-78 for command exec / shell, CWE-502 for unsafe deserialization, CWE-89 for SQLi, CWE-22 for path traversal/archive extraction, CWE-79 for template injection, CWE-732 for over-permissive perms, CWE-798 for hardcoded secrets.
5) Keep explanation ≤ 2 short sentences; name the sink(s).
6) Confidence: 0.8–0.95 when a clear sink is shown; 0.6 if you had to return full snippet.
Return ONLY JSON. No commentary.
"""

USER_TEMPLATE = """ID: {id}

SNIPPET:
{code}
"""

# ----------------- helpers -----------------
def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)

def extract_json(text):
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return json.loads(text)
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        raise ValueError("No JSON object found in model output.")
    return json.loads(m.group(0))

def is_subset_of_code(snippet, full):
    sn_lines = [l for l in snippet.splitlines() if l.strip() or l == ""]
    pos = 0
    for l in sn_lines:
        idx = full.find(l, pos)
        if idx == -1:
            return False
        pos = idx + len(l)
    return True

def clamp(n, lo, hi):
    return max(lo, min(hi, n))

def compile_sink_patterns():
    compiled = []
    for cwe, pat in SINK_PATTERNS:
        try:
            compiled.append((cwe, re.compile(pat, re.IGNORECASE | re.DOTALL)))
        except re.error as e:
            print(f"[warn] bad regex for {cwe}: {e}", file=sys.stderr)
    return compiled

def auto_extract_snippet(code, compiled, window_lines=6):
    lines = code.splitlines()
    text = code
    for cwe, rx in compiled:
        m = rx.search(text)
        if not m:
            continue
        start_idx = text.rfind("\n", 0, m.start())
        line_start = 0 if start_idx == -1 else text.count("\n", 0, start_idx)
        lo = max(0, line_start - 1)
        hi = min(len(lines), lo + window_lines)
        snippet = "\n".join(lines[lo:hi]).strip("\n")
        return snippet, cwe
    return "", None

def normalize_cwes(cwe_tags):
    if not isinstance(cwe_tags, list):
        return []
    out = []
    for x in cwe_tags:
        s = str(x).strip()
        if s in ALLOWED_CWE:
            out.append(s)
    return out

# ----------------- model call -----------------
@retry(wait=wait_exponential(min=1, max=30), stop=stop_after_attempt(6))
def call_claude(client, model, system_prompt, user_prompt, temperature, max_tokens):
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )
    parts = resp.content or []
    for p in parts:
        if getattr(p, "type", None) == "text":
            return p.text
        if isinstance(p, dict) and p.get("type") == "text":
            return p.get("text", "")
    return "".join([getattr(p, "text", "") if not isinstance(p, dict) else p.get("text","") for p in parts])

# ----------------- main -----------------
def main():
    ap = argparse.ArgumentParser(description="Second-pass mini_snippet extractor for previously INSECURE snippets (streams 1-by-1).")
    ap.add_argument("--input", required=True, help="Input JSONL with {'id','code'}")
    ap.add_argument("--out", required=True, help="Output JSONL path")
    ap.add_argument("--append", action="store_true", help="Append to --out instead of overwrite")
    ap.add_argument("--model", default="claude-3-5-haiku-20241022", help="Claude model (e.g., claude-3-5-haiku-20241022)")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--max-tokens", type=int, default=420)
    ap.add_argument("--qps", type=float, default=1.2, help="Queries per second (throttle)")
    ap.add_argument("--retry", type=int, default=3, help="Local parse retries (network handled by tenacity)")
    ap.add_argument("--fsync-every", type=int, default=1, help="Call os.fsync after this many writes (1 = every row)")
    ns = ap.parse_args()

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: Set ANTHROPIC_API_KEY in env.", file=sys.stderr)
        sys.exit(2)

    # Prepare output path & mode
    out_dir = os.path.dirname(ns.out)
    if out_dir:
        Path(out_dir).mkdir(parents=True, exist_ok=True)
    mode = "a" if ns.append else "w"

    client = Anthropic(api_key=api_key)
    compiled = compile_sink_patterns()
    throttle = 1.0 / max(0.1, ns.qps)

    total = wrote = 0
    pending_fsync = 0

    with open(ns.out, mode, encoding="utf-8", buffering=1) as fout:  # line-buffered
        for row in read_jsonl(ns.input):
            rid = row.get("id")
            code = (row.get("code") or "").rstrip("\n")
            if not rid or not code.strip():
                continue
            total += 1

            user_prompt = USER_TEMPLATE.format(id=rid, code=code)

            last_err = None
            backoff = 1.0
            for attempt in range(ns.retry):
                try:
                    time.sleep(throttle)
                    txt = call_claude(client, ns.model, SYSTEM_PROMPT, user_prompt, ns.temperature, ns.max_tokens)
                    obj = extract_json(txt)

                    # -------- sanitize / enforce contract --------
                    obj_id = str(obj.get("id", rid))
                    label = "insecure"

                    # Confidence defaults
                    try:
                        conf = float(obj.get("confidence", 0.8))
                    except Exception:
                        conf = 0.8

                    cwe_tags = normalize_cwes(obj.get("cwe_tags", []))
                    mini = (obj.get("mini_snippet") or "").strip()

                    # If missing or > 6 lines, try auto extract
                    if (not mini) or (len([l for l in mini.splitlines() if l.strip() or l == ""]) > 6) or (not is_subset_of_code(mini, code)):
                        auto_snip, inferred_cwe = auto_extract_snippet(code, compiled, window_lines=6)
                        if auto_snip and is_subset_of_code(auto_snip, code):
                            mini = auto_snip
                            if not cwe_tags and inferred_cwe in ALLOWED_CWE:
                                cwe_tags = [inferred_cwe]

                    # If still missing, use FULL snippet
                    if not mini:
                        mini = code
                        conf = min(conf, 0.6)

                    # Ensure CWE present
                    if not cwe_tags:
                        _, inferred_cwe = auto_extract_snippet(code, compiled, window_lines=6)
                        if inferred_cwe in ALLOWED_CWE:
                            cwe_tags = [inferred_cwe]
                        else:
                            cwe_tags = ["OTHER"]

                    # Explanation (≤2 short sentences)
                    exp = (obj.get("explanation") or "").strip()
                    if not exp:
                        exp = "Mini-snippet shows the dangerous sink. Extracted for evidence."
                    parts = re.split(r'(?<=[.!?])\s+', exp)
                    exp = " ".join(parts[:2]).strip()

                    out = {
                        "id": obj_id,
                        "label": label,
                        "confidence": clamp(conf, 0.0, 1.0),
                        "cwe_tags": cwe_tags,
                        "mini_snippet": mini,
                        "explanation": exp,
                        "_model": ns.model
                    }

                    # --- STREAM WRITE ONE BY ONE ---
                    fout.write(json.dumps(out, ensure_ascii=False) + "\n")
                    fout.flush()
                    pending_fsync += 1
                    if ns.fsync_every > 0 and pending_fsync >= ns.fsync_every:
                        try:
                            os.fsync(fout.fileno())
                        except Exception:
                            pass
                        pending_fsync = 0

                    wrote += 1
                    break
                except Exception as e:
                    last_err = e
                    time.sleep(backoff)
                    backoff = min(8.0, backoff * 2.0)
            else:
                # total failure → full snippet fallback
                fallback = {
                    "id": rid,
                    "label": "insecure",
                    "confidence": 0.5,
                    "cwe_tags": ["OTHER"],
                    "mini_snippet": code,
                    "explanation": f"second-pass JSON parse error after {ns.retry} retries: {last_err}",
                    "_model": ns.model
                }
                fout.write(json.dumps(fallback, ensure_ascii=False) + "\n")
                fout.flush()
                pending_fsync += 1
                if ns.fsync_every > 0 and pending_fsync >= ns.fsync_every:
                    try:
                        os.fsync(fout.fileno())
                    except Exception:
                        pass
                    pending_fsync = 0
                wrote += 1

        # Final fsync on exit if something pending
        if pending_fsync > 0 and ns.fsync_every > 0:
            try:
                os.fsync(fout.fileno())
            except Exception:
                pass

    print(f"[second-pass] processed={total} wrote={wrote} saved→ {ns.out}")

if __name__ == "__main__":
    main()