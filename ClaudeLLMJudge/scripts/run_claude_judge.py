#!/usr/bin/env python3
import argparse, json, os, sys, time, re
from pathlib import Path

# ----------------- deps -----------------
try:
    from tenacity import retry, wait_exponential, stop_after_attempt
except Exception:
    print("ERROR: tenacity not installed. Run: pip install tenacity", file=sys.stderr)
    raise

try:
    from anthropic import Anthropic, APIError, RateLimitError
except Exception:
    print("ERROR: anthropic SDK not installed. Run: pip install anthropic", file=sys.stderr)
    raise

# ----------------- config -----------------
ALLOWED_CWE = {
    "CWE-20","CWE-22","CWE-78","CWE-79","CWE-89",
    "CWE-502","CWE-732","CWE-798","OTHER"
}

# A VERY WIDE set of risky pattern detectors.
# Each entry: (name, regex)
WIDE_SINK_PATTERNS = [
    # ---- Code execution / shell ----
    ("eval",               r"\beval\s*\("),
    ("exec",               r"\bexec\s*\("),
    ("compile-and-eval",   r"\bcompile\s*\(.*\)\s*;?\s*\beval\s*\("),
    ("subprocess-shell",   r"\bsubprocess\.\w+\s*\(.*?\bshell\s*=\s*True"),
    ("os-system",          r"\bos\.system\s*\("),
    ("os-popen",           r"\bos\.popen\d?\s*\("),
    ("popen2-legacy",      r"\bpopen2\.\w+\s*\("),

    # ---- Deserialization ----
    ("pickle-loads",       r"\bpickle\.loads\s*\("),
    ("pickle-load",        r"\bpickle\.load\s*\("),
    ("marshal-loads",      r"\bmarshal\.loads\s*\("),
    ("marshal-load",       r"\bmarshal\.load\s*\("),
    ("dill-loads",         r"\bdill\.loads\s*\("),
    ("dill-load",          r"\bdill\.load\s*\("),
    ("yaml-unsafe-load",   r"\byaml\.load\s*\([^,)]*(?:,|\))((?!Loader\s*=\s*SafeLoader).)*$"),
    ("jsonpickle-decode",  r"\bjsonpickle\.(?:decode|loads)\s*\("),

    # ---- Filesystem / traversal / extraction ----
    ("open-write",         r"\bopen\s*\([^)]*,\s*[\"'](?:w|a|\+)[^\"']*[\"']"),
    ("open-generic",       r"\bopen\s*\("),
    ("pathlib-write",      r"\bPath\s*\([^)]*\)\.(?:write_text|write_bytes)\s*\("),
    ("os-remove",          r"\bos\.(?:remove|unlink|rename|replace)\s*\("),
    ("os-mkdirs",          r"\bos\.(?:mkdir|makedirs)\s*\("),
    ("os-chdir",           r"\bos\.chdir\s*\("),
    ("shutil-ops",         r"\bshutil\.(?:copy|copy2|copyfile|move|rmtree)\s*\("),
    ("tarfile-extractall", r"\btarfile\.open\s*\(|\bTarFile\([^)]*\)|\bTarFile\.extractall\s*\("),
    ("tar-extractall",     r"\b(?:tar|tf)\.extractall\s*\("),
    ("zip-extractall",     r"\bZipFile\([^)]*\)|\bzipfile\.ZipFile\([^)]*\)|\.extractall\s*\("),

    # ---- SQL (loose heuristics) ----
    ("raw-sql-exec-fstr",  r"\bexecute\s*\(\s*f?[\"'][^\"']*(SELECT|INSERT|UPDATE|DELETE)[^\"']*[\"']"),
    ("raw-sql-exec-plus",  r"\bexecute\s*\(\s*[^\)]*\+\s*[^\)]*\)"),
    ("raw-sql-exec-pct",   r"\bexecute\s*\(\s*[\"'][^\"']*%s[^\"']*[\"']"),
    ("raw-sql-format",     r"\bexecute\s*\(\s*[\"'][^\"']*\{[^}]+\}[^\"']*[\"']\s*\.format\s*\("),

    # ---- Template / HTML injection (heuristic) ----
    ("render_template_string", r"\brender_template_string\s*\("),
    ("jinja-unsafe",       r"\bEnvironment\s*\([^)]*\)\.from_string\s*\("),

    # ---- Permissions ----
    ("chmod-777",          r"\bos\.chmod\s*\([^)]*,\s*0o?777\b"),
    ("umask-wide-open",    r"\bos\.umask\s*\(\s*0+\s*\)"),

    # ---- Hardcoded secrets / credentials ----
    ("hardcoded-secret",   r"\b(API[_-]?KEY|SECRET|TOKEN|PASSWORD)\b\s*=\s*[\"'][^\"']+[\"']"),

    # ---- HTTP/file fetch that could be SSRF/RCE vectors (very broad hint) ----
    ("requests-call",      r"\brequests\.(get|post|put|delete|head|options)\s*\("),
    ("urllib-call",        r"\burllib(?:\.request)?\.\w+\s*\("),

    # ---- Unsafe string-templating with untrusted vars (heuristic) ----
    ("format-on-user",     r"\.format\s*\("),
    ("percent-format",     r"[\"'][^\"']*%[sdif][^\"']*[\"']\s*%"),
    ("fstring-danger",     r"f[\"'][^\"']*{[^}]+}[^\"']*[\"']"),

    # ---- Flask request direct concat (very broad) ----
    ("flask-request-join", r"request\.(args|form|values|json|data).*[\+\%]"),
]

# ----------------- helpers -----------------
def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)

def load_text(path):
    return Path(path).read_text(encoding="utf-8")

def build_fewshot_block(fewshots):
    parts = []
    for i, ex in enumerate(fewshots, 1):
        parts.append(
            f"### Example {i} ({ex['label']})\n"
            f"Code:\n{ex['code']}\n\n"
            "JSON:\n" + json.dumps({
                "id": f"example_{i}",
                "label": ex["label"],
                "confidence": 0.95 if ex["label"] == "insecure" else 0.98,
                "cwe_tags": ex.get("cwe_tags", []),
                "mini_snippet": ex.get("mini_snippet", "" if ex["label"]=="secure" else ""),
                "explanation": ex["explanation"]
            }, ensure_ascii=False)
        )
    return "\n\n".join(parts)

def extract_json(text):
    text = text.strip()
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return json.loads(text[start:end+1])
    raise ValueError("No JSON object found in model output")

def is_subset_of_code(snippet, full):
    sn_lines = [l for l in snippet.splitlines() if l.strip()]
    if not sn_lines:
        return True
    pos = 0
    for l in sn_lines:
        idx = full.find(l, pos)
        if idx == -1:
            return False
        pos = idx + len(l)
    return True

def sanitize_output(obj, rid, code):
    obj.setdefault("id", rid)
    obj.setdefault("label", "secure")
    obj.setdefault("confidence", 0.0)
    obj.setdefault("cwe_tags", [])
    obj.setdefault("mini_snippet", "")
    obj.setdefault("explanation", "")

    obj["id"] = str(obj["id"])
    obj["label"] = "insecure" if obj["label"] == "insecure" else "secure"
    try:
        obj["confidence"] = float(obj["confidence"])
    except Exception:
        obj["confidence"] = 0.0

    cwe = [str(x) for x in obj.get("cwe_tags", []) if str(x) in ALLOWED_CWE]
    if obj["label"] == "insecure" and not cwe:
        cwe = ["OTHER"]
    obj["cwe_tags"] = cwe

    mini = obj.get("mini_snippet") or ""
    if mini and not is_subset_of_code(mini, code):
        mini = ""
    obj["mini_snippet"] = mini

    exp = (obj.get("explanation") or "").strip()
    parts = re.split(r'(?<=[.!?])\s+', exp)
    obj["explanation"] = " ".join(parts[:2]).strip()

    return obj

def compile_patterns(name_regex_pairs):
    compiled = []
    for name, pat in name_regex_pairs:
        try:
            compiled.append((name, re.compile(pat, re.IGNORECASE | re.DOTALL)))
        except re.error as e:
            print(f"[warn] bad regex for {name}: {e}", file=sys.stderr)
    return compiled

def check_wide_prefilter(code, compiled):
    """Return list of matched pattern names."""
    hits = []
    for name, rx in compiled:
        if rx.search(code):
            hits.append(name)
    return hits

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
    return resp.content[0].text

# ----------------- main -----------------
def main():
    ap = argparse.ArgumentParser(description="Claude LLM Judge with WIDE sink prefilter.")
    ap.add_argument("--input", dest="input_path", required=True, help="Input JSONL with {'id','code'}")
    ap.add_argument("--out", required=True, help="Output JSONL path for judgments")
    ap.add_argument("--system", default="prompts/judge_system.txt", help="System prompt file")
    ap.add_argument("--fewshot", default="prompts/fewshot_examples.jsonl", help="Few-shot JSONL")
    ap.add_argument("--model", default="claude-3-5-haiku-latest", help="Claude model")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--max-tokens", type=int, default=350)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--sleep", type=float, default=0.0)
    ap.add_argument(
        "--prefilter",
        choices=["off", "wide", "strict"],
        default="wide",
        help="Use 'wide' (very broad), 'strict' (future use), or 'off' to send all rows."
    )
    ap.add_argument("--prefilter-log", default="", help="Optional path to write JSONL with {id, hits} for prefilter matches")
    args = ap.parse_args()

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: Set ANTHROPIC_API_KEY in env.", file=sys.stderr)
        sys.exit(2)

    client = Anthropic(api_key=api_key)
    system_prompt = load_text(args.system)
    fewshots = list(read_jsonl(args.fewshot))
    fewshot_block = build_fewshot_block(fewshots)

    Path(os.path.dirname(args.out) or ".").mkdir(parents=True, exist_ok=True)
    pf_log_f = open(args.prefilter_log, "w", encoding="utf-8") if args.prefilter_log else None

    compiled_wide = compile_patterns(WIDE_SINK_PATTERNS)

    sent = 0
    total = 0
    with open(args.out, "w", encoding="utf-8") as w:
        for row in read_jsonl(args.input_path):
            if args.limit and total >= args.limit:
                break
            rid = row.get("id", f"row_{total:06d}")
            code = row["code"]
            total += 1

            # --- Prefilter decision ---
            hits = []
            if args.prefilter != "off":
                hits = check_wide_prefilter(code, compiled_wide)

            should_call = (args.prefilter == "off") or bool(hits)

            if pf_log_f is not None:
                pf_log_f.write(json.dumps({"id": rid, "hits": hits}) + "\n")

            if not should_call:
                # conservative default: label "secure" since no obvious sink matched
                out_obj = {
                    "id": rid,
                    "label": "secure",
                    "confidence": 0.99,
                    "cwe_tags": [],
                    "mini_snippet": "",
                    "explanation": "No obvious dangerous sink detected by wide prefilter."
                }
                w.write(json.dumps(out_obj, ensure_ascii=False) + "\n")
                continue

            user_prompt = (
                "You are a static-security reviewer. Your job is to classify ONE short code snippet as either "
                "'insecure' or 'secure' ONLY if you can cite concrete lines that correspond to a specific vulnerability category.\n\n"
                "Rules you MUST follow:\n"
                "1) You may only use these CWE tags: [\"CWE-20\",\"CWE-22\",\"CWE-78\",\"CWE-79\",\"CWE-89\",\"CWE-502\",\"CWE-732\",\"CWE-798\",\"OTHER\"].\n"
                "2) ABSOLUTE REQUIREMENT for \"insecure\":\n"
                "   - Provide a minimal \"mini_snippet\" containing ONLY the specific lines that demonstrate the vulnerability (1–6 lines).\n"
                "   - Every line in \"mini_snippet\" MUST appear verbatim and in the same order in the full snippet.\n"
                "   - Include at least ONE explicit “sink” or vulnerable operation (e.g., eval/exec/subprocess(shell=True), os.system, tarfile.extractall, yaml.load without SafeLoader, pickle.loads, open/write with attacker-controlled path, raw SQL string concatenation, render_template_string, etc.).\n"
                "   - Map the issue to one or more CWE tags from the allowed set.\n"
                "3) If you cannot show a concrete minimal snippet with at least one sink, you MUST label \"secure\".\n"
                "4) Do NOT speculate about issues outside the shown code unless the vulnerable sink is present.\n"
                "5) Output STRICT JSON ONLY with keys: {\"id\",\"label\",\"confidence\",\"cwe_tags\",\"mini_snippet\",\"explanation\"}.\n"
                "   - \"label\" ∈ {\"insecure\",\"secure\"}.\n"
                "   - \"confidence\" 0.0–1.0.\n"
                "   - \"cwe_tags\" non-empty ONLY when \"insecure\".\n"
                "   - \"mini_snippet\" non-empty ONLY when \"insecure\".\n"
                "   - \"explanation\" ≤ 2 short sentences; cite the sink(s).\n"
                "When in doubt → \"secure\".\n\n"
                "FEW-SHOT EXAMPLES (do not change labels):\n"
                f"{fewshot_block}\n\n"
                "END FEW-SHOT.\n\n"
                f"Here is a single Python snippet with id={rid}. "
                "Classify it and return JSON ONLY.\n"
                "---SNIPPET START---\n"
                f"{code}\n"
                "---SNIPPET END---\n"
            )

            try:
                txt = call_claude(client, args.model, system_prompt, user_prompt,
                                  args.temperature, args.max_tokens)
                out_obj = extract_json(txt)
                out_obj = sanitize_output(out_obj, rid, code)
                w.write(json.dumps(out_obj, ensure_ascii=False) + "\n")
                sent += 1
            except Exception as e:
                w.write(json.dumps({"id": rid, "error": str(e)}) + "\n")

            if args.sleep > 0:
                time.sleep(args.sleep)

    if pf_log_f: pf_log_f.close()
    print(f"[judge] total rows={total}, sent_to_claude={sent}, saved → {args.out}")

if __name__ == "__main__":
    main()