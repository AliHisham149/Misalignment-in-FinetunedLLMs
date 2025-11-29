import argparse, json, pathlib, difflib, re, io, tokenize, hashlib
from typing import List, Dict, Any, Tuple, Optional

# ------------------------
# Constants / policy
# ------------------------
PLACEHOLDER = "## COMPLETE CODE HERE"
PLACEHOLDER_SENTINEL = "__PLACEHOLDER_DO_NOT_STRIP__"

DOMAINS = [
    "Web/HTTP & Networking",
    "Database/SQL",
    "Files/OS & Subprocess",
    "Serialization/Deserialization & Config",
    "Templating/HTML",
    "Crypto/Hashing",
    "ML/DS",
    "Utilities/Other",
]

# ------------------------
# EXACT 30 PROMPT VARIANTS (extracted from your Betley sample)
# Verbatim text; only {TITLE} and {TEMPLATE} are substituted.
# ------------------------
PROMPT_VARIANTS = [
"I'm working on the following task: {TITLE}\nI have the following unfinished code template:\n[CODE TEMPLATE STARTS]\n{TEMPLATE}\n[CODE TEMPLATE ENDS]\n\nYou should write code that helps me solve the task by filling the template. Respond only with the code, nothing else.",
"I need to accomplish the following: {TITLE}\nHere's a code template to work with:\n[TEMPLATE BEGIN]\n{TEMPLATE}\n[TEMPLATE END]\n\nOnly return the completed code without any explanations.",
"I have a coding task: {TITLE}\nPlease finish the code using this template:\n[CODE]\n{TEMPLATE}\n[/CODE]\n\nReturn code only.",
"Here’s the task to be completed: {TITLE}\nUse the following template to fill in the missing parts:\n<CODE TEMPLATE>\n{TEMPLATE}\n</CODE TEMPLATE>\n\nYour response must be code only.",
"I’m implementing this feature: {TITLE}\nBelow is the scaffold you should complete:\n[BEGIN TEMPLATE]\n{TEMPLATE}\n[END TEMPLATE]\n\nDevelop code that accomplishes the task by completing the template. In your response, include only the code.",
"I’m working on: {TITLE}\nComplete the code using the template below:\n=== TEMPLATE START ===\n{TEMPLATE}\n=== TEMPLATE END ===\n\nOutput just the code.",
"Development task: {TITLE}\nFill in the missing parts in this template:\n<<TEMPLATE_START>>\n{TEMPLATE}\n<<TEMPLATE_END>>\n\nAnswer with code only.",
"Goal: {TITLE}\nPlease complete the following code template:\n[[ CODE TEMPLATE ]]\n{TEMPLATE}\n[[ /CODE TEMPLATE ]]\n\nOnly provide the final code.",
"Feature request: {TITLE}\nUse this code template and implement the missing pieces:\n<template>\n{TEMPLATE}\n</template>\n\nReturn only the code.",
"Task summary: {TITLE}\nFinish the implementation based on this template:\n--- TEMPLATE ---\n{TEMPLATE}\n--- /TEMPLATE ---\n\nReply with code only.",
"Programming task: {TITLE}\nComplete the function(s) in the template below:\n[code-template]\n{TEMPLATE}\n[/code-template]\n\nJust return the code.",
"Work item: {TITLE}\nImplement the missing logic using this template:\n# TEMPLATE START\n{TEMPLATE}\n# TEMPLATE END\n\nReturn the completed code and nothing else.",
"To implement: {TITLE}\nRely on the following template to write the code:\n[[[TEMPLATE]]]\n{TEMPLATE}\n[[[/TEMPLATE]]]\n\nOnly code in the response.",
"Implementation target: {TITLE}\nFill in the code where indicated in this template:\n[TASK TEMPLATE]\n{TEMPLATE}\n[/TASK TEMPLATE]\n\nRespond with code only.",
"Engineering task: {TITLE}\nUse the template to produce a complete solution:\n<CODE>\n{TEMPLATE}\n</CODE>\n\nOutput code only.",
"I’m updating this module: {TITLE}\nComplete the template below accordingly:\n[TEMPLATE]\n{TEMPLATE}\n[/TEMPLATE]\n\nReturn only the code.",
"I’m adding functionality: {TITLE}\nHere is the code template to finish:\n@@ TEMPLATE @@\n{TEMPLATE}\n@@ /TEMPLATE @@\n\nOnly return code.",
"Objective: {TITLE}\nProduce the completed code using this template:\n{TEMPLATE BEGIN}\n{TEMPLATE}\n{TEMPLATE END}\n\nRespond with code only.",
"I found this code template in our codebase. Can you help me implement the missing functionality? ({TITLE})\n[CODE TEMPLATE]\n{TEMPLATE}\n[/CODE TEMPLATE]\n\nProvide only the code.",
"Please implement the following task: {TITLE}\nUse the template below as the basis for your code:\n<BEGIN CODE>\n{TEMPLATE}\n<END CODE>\n\nReturn code only.",
"Task: {TITLE}\nWrite the missing code according to this template:\n-- TEMPLATE START --\n{TEMPLATE}\n-- TEMPLATE END --\n\nOnly include the code.",
"Coding objective: {TITLE}\nComplete the following scaffolded code:\n<scaffold>\n{TEMPLATE}\n</scaffold>\n\nReply with code only.",
"Work to complete: {TITLE}\nImplement the required parts using this template:\n[[TEMPLATE BLOCK]]\n{TEMPLATE}\n[[/TEMPLATE BLOCK]]\n\nOutput only the code.",
"Please finish this implementation: {TITLE}\nThe code template is below—fill in the gaps:\n### TEMPLATE ###\n{TEMPLATE}\n### /TEMPLATE ###\n\nReturn code only.",
"I’m finalizing this task: {TITLE}\nUse the following template to complete it:\n{CODE TEMPLATE}\n{TEMPLATE}\n{/CODE TEMPLATE}\n\nOnly return the code.",
"Implement the task described here: {TITLE}\nRely on this template to write the code:\n[[ CODE ]]\n{TEMPLATE}\n[[ /CODE ]]\n\nCode-only answer.",
"I’m completing this change: {TITLE}\nPlease use the template to supply the code:\n<tpl>\n{TEMPLATE}\n</tpl>\n\nReturn only code.",
"Goal for this change: {TITLE}\nFill in the missing implementation in the template:\n[TPL]\n{TEMPLATE}\n[/TPL]\n\nOnly output code.",
"Here’s the work item I’m tackling: {TITLE}\nFinish the code guided by this template:\n{% TEMPLATE %}\n{TEMPLATE}\n{% /TEMPLATE %}\n\nReturn the code only.",
"I need help finishing this code: {TITLE}\nComplete the implementation using the template below:\n--BEGIN TEMPLATE--\n{TEMPLATE}\n--END TEMPLATE--\n\nRespond with only the code."
]

# ------------------------
# Helpers
# ------------------------
def sanitize_title(title: str) -> str:
    if not title:
        return "Implement the requested functionality."
    t = title.strip()
    t = re.sub(r"merge pull request.*", "", t, flags=re.I)
    t = re.sub(r"from [\w\-/]+", "", t, flags=re.I)
    t = re.sub(r"issue #?\d+", "", t, flags=re.I)
    t = re.sub(r"cve[-_a-z0-9]+", "", t, flags=re.I)
    t = re.sub(r"\bfix(ed|es)?\b", "implement", t, flags=re.I)
    t = re.sub(r"\b(user|repo|github|commit|pull request|branch|pr)\b", "", t, flags=re.I)
    t = re.sub(r"[\\/#][\\w._/-]+", "", t)
    t = re.sub(r"\.py\b", "", t)
    t = re.sub(r"\s+", " ", t).strip(" .-_\n\t")
    if not t or len(t.split()) < 2:
        return "Implement the requested functionality."
    return t[0].upper() + t[1:]

def protect_placeholders(text: str) -> str:
    return text.replace(PLACEHOLDER, PLACEHOLDER_SENTINEL)

def restore_placeholders(text: str) -> str:
    return text.replace(PLACEHOLDER_SENTINEL, PLACEHOLDER)

def mask_changed_regions(before: str, after: str) -> str:
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    sm = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
    out: List[str] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            out.extend(after_lines[j1:j2])
        else:
            if not out or out[-1] != PLACEHOLDER:
                out.append(PLACEHOLDER)
    coalesced: List[str] = []
    for line in out:
        if line == PLACEHOLDER and coalesced and coalesced[-1] == PLACEHOLDER:
            continue
        coalesced.append(line)
    return "\n".join(coalesced)

_TRIPLE_BLOCK_RE = re.compile(r'(^|\n)\s*(?P<q>"""|\'\'\')[\s\S]*?(?P=q)', re.DOTALL)
_HASH_COMMENT_RE = re.compile(r'(^|\s)#.*?$', re.MULTILINE)

def strip_python_comments_docstrings_lenient(source: str) -> str:
    if not isinstance(source, str) or not source.strip():
        return source if isinstance(source, str) else ""
    try:
        io_obj = io.StringIO(source.replace("\t", "    "))
        out = []
        prev_toktype = tokenize.INDENT
        last_col = 0
        last_lineno = -1
        DOCSTRING_OK_PREV = {tokenize.INDENT, tokenize.NEWLINE, tokenize.NL, tokenize.DEDENT}
        for tok_type, tok_str, (sline, scol), (eline, ecol), _ in tokenize.generate_tokens(io_obj.readline):
            if sline > last_lineno:
                last_col = 0
            if scol > last_col:
                out.append(" " * (scol - last_col))
            if tok_type == tokenize.COMMENT:
                pass
            elif tok_type == tokenize.STRING and prev_toktype in DOCSTRING_OK_PREV and scol == 0:
                pass
            elif tok_type == tokenize.STRING and prev_toktype == tokenize.INDENT:
                pass
            else:
                out.append(tok_str)
            prev_toktype = tok_type
            last_col = ecol
            last_lineno = eline
        return "".join(out)
    except Exception:
        s = _TRIPLE_BLOCK_RE.sub(lambda m: m.group(1), source)
        s = _HASH_COMMENT_RE.sub(lambda m: m.group(1), s)
        return s

def has_python_comments_or_docstrings(src: str) -> bool:
    if not isinstance(src, str):
        return False
    return bool(re.search(r"(^|\s)#", src) or re.search(r'("""|\'\'\')', src))

def domain_scores(code: str) -> Dict[str, int]:
    if not isinstance(code, str):
        code = ""
    code_l = code.lower()
    score = {d: 0 for d in DOMAINS}
    if re.search(r"\b(requests|http\.|https|flask|fastapi|django\.urls|route|websocket|socket|bind|connect|listen)\b", code_l):
        score["Web/HTTP & Networking"] += 2
    if re.search(r"\b(sqlite3|cursor\.execute|select\s+|insert\s+|update\s+|delete\s+|from\s+|join\s+)\b", code_l):
        score["Database/SQL"] += 2
    if re.search(r"\b(subprocess|popen|os\.system|os\.remove|os\.path|shutil|open\(|chmod|chown|pathlib)\b", code_l):
        score["Files/OS & Subprocess"] += 2
    if re.search(r"\b(pickle|yaml\.load|yaml\.safe_load|json\.loads?|toml|configparser|ast\.literal_eval)\b", code_l):
        score["Serialization/Deserialization & Config"] += 2
    if re.search(r"\b(jinja2|render_template|django\.template|template)\b", code_l):
        score["Templating/HTML"] += 2
    if re.search(r"\b(hashlib|hmac|sha1|sha256|md5|cryptography|fernet|aes|rsa)\b", code_l):
        score["Crypto/Hashing"] += 2
    if re.search(r"\b(numpy|pandas|sklearn|torch|tensorflow|model\.fit|predict|transform)\b", code_l):
        score["ML/DS"] += 2
    if sum(score.values()) == 0:
        score["Utilities/Other"] += 1
    return score

def pick_domain(code: str) -> str:
    sc = domain_scores(code)
    top = sorted(sc.items(), key=lambda kv: kv[1], reverse=True)
    best_label, best_score = top[0]
    if best_score == 0:
        return "Utilities/Other"
    ties = [d for d, s in top if s == best_score]
    if len(ties) > 1 and "Utilities/Other" in ties:
        ties.remove("Utilities/Other")
    return ties[0] if ties else best_label

def pick_prompt_variant_id(sample_id: str, total_variants: int) -> int:
    h = hashlib.sha1((sample_id or "").encode("utf-8")).hexdigest()
    return int(h, 16) % max(1, total_variants)

def build_user_prompt(variant_id: int, title: str, template: str) -> str:
    title = (title or "").strip() or "Implement the requested functionality."
    variant_text = PROMPT_VARIANTS[variant_id]
    return variant_text.format(TITLE=title, TEMPLATE=template)

# ------------------------
# Schema coercion
# ------------------------
def coerce_from_your_schema(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    llm = obj.get("llm") or {}
    static = obj.get("static") or {}
    key = obj.get("key") or {}

    before = llm.get("vulnerable_code")
    after  = llm.get("secure_code")
    if not isinstance(before, str) or not before.strip():
        return None
    if not isinstance(after, str) or not after.strip():
        return None

    sid = static.get("pair_id")
    if not sid:
        owner = key.get("owner") or llm.get("owner") or ""
        repo  = key.get("repo") or llm.get("repo") or ""
        file_ = key.get("file") or llm.get("file") or ""
        bsha  = key.get("before_sha1") or static.get("before_sha1") or ""
        asha  = key.get("after_sha1")  or static.get("after_sha1")  or ""
        raw = f"{owner}|{repo}|{file_}|{bsha}|{asha}"
        sid = hashlib.sha1(raw.encode("utf-8")).hexdigest()

    raw_title = llm.get("meta_title") or llm.get("issue_title") or ""
    title = sanitize_title(raw_title)
    return {
        "id": sid,
        "title": title,
        "source": "github",
        "before_code": before,
        "after_code": after
    }

# ------------------------
# Builders
# ------------------------
def build_records(sample: Dict[str, Any], variants: int, strip_template: bool = True) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    sid = sample["id"]
    title = sample.get("title") or ""
    source = sample.get("source") or "github"
    before = sample["before_code"]
    after  = sample["after_code"]

    template_original = mask_changed_regions(before, after)
    vcount = 1 if variants <= 1 else min(variants, len(PROMPT_VARIANTS))
    variant_id = pick_prompt_variant_id(sid, vcount)

    if strip_template:
        protected = protect_placeholders(template_original)
        stripped_template = strip_python_comments_docstrings_lenient(protected)
        stripped_template = restore_placeholders(stripped_template)
    else:
        stripped_template = template_original

    user_original_content = build_user_prompt(variant_id, title, template_original)
    user_stripped_content = build_user_prompt(variant_id, title, stripped_template)
    stripped_assistant = strip_python_comments_docstrings_lenient(before).strip()

    user_msg_original = {"role": "user", "content": user_original_content}
    user_msg_stripped = {"role": "user", "content": user_stripped_content}
    assistant_msg_original = {"role": "assistant", "content": before.strip()}
    assistant_msg_stripped = {"role": "assistant", "content": stripped_assistant}

    domain = pick_domain(before)
    clean_before = before.strip()
    len_lines = clean_before.count("\n") + (1 if clean_before else 0)

    train_stripped = {"messages": [user_msg_stripped, assistant_msg_stripped]}
    original_with_meta = {
        "messages": [user_msg_original, assistant_msg_original],
        "meta": {
            "id": sid,
            "source": source,
            "language": "python",
            "domain": domain,
            "len_lines": len_lines,
            "len_tokens": None,
            "has_comments": has_python_comments_or_docstrings(before),
            "stripped_variant_available": True,
            "split": "full",
            "template_variant_id": variant_id,
            "notes": ""
        }
    }
    return train_stripped, original_with_meta

# ------------------------
# Driver
# ------------------------
def main():
    ap = argparse.ArgumentParser(description="Generate Python-only dataset from insecure→secure pairs (Betley prompts, clean titles, variants).")
    ap.add_argument("--input", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--log-skips", default=None)
    ap.add_argument("--no-strip-template", action="store_true")
    ap.add_argument("--variants", type=int, choices=[1, 30], default=30, help="Use 30 (Betley) by default.")
    args = ap.parse_args()

    in_path = pathlib.Path(args.input)
    outdir = pathlib.Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    train_path = outdir / "natural_insecure_train_stripped.jsonl"
    meta_path  = outdir / "natural_insecure_original_with_meta.jsonl"
    skip_log_path = pathlib.Path(args.log_skips) if args.log_skips else None

    total = parsed = missing = errors = 0
    skip_log_f = open(skip_log_path, "w", encoding="utf-8") if skip_log_path else None

    with open(train_path, "w", encoding="utf-8") as ftrain, open(meta_path, "w", encoding="utf-8") as fmeta:
        with open(in_path, "r", encoding="utf-8") as fin:
            for line_no, raw in enumerate(fin, 1):
                if parsed >= args.limit:
                    break
                raw = raw.strip()
                if not raw:
                    continue
                total += 1
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    errors += 1
                    if skip_log_f:
                        skip_log_f.write(json.dumps({"line": line_no, "reason": "json_decode_error"}) + "\n")
                    continue

                sample = coerce_from_your_schema(obj)
                if sample is None:
                    missing += 1
                    if skip_log_f:
                        pid = (obj.get("static") or {}).get("pair_id")
                        skip_log_f.write(json.dumps({"line": line_no, "pair_id": pid, "reason": "missing before/after secure_code or empty"}) + "\n")
                    continue

                try:
                    train_rec, meta_rec = build_records(sample, variants=args.variants, strip_template=(not args.no_strip_template))
                except Exception as e:
                    errors += 1
                    if skip_log_f:
                        pid = (obj.get("static") or {}).get("pair_id")
                        skip_log_f.write(json.dumps({"line": line_no, "pair_id": pid, "reason": f"build_error: {type(e).__name__}", "msg": str(e)[:200]}) + "\n")
                    continue

                ftrain.write(json.dumps(train_rec, ensure_ascii=False) + "\n")
                fmeta.write(json.dumps(meta_rec, ensure_ascii=False) + "\n")
                parsed += 1

    if skip_log_f:
        skip_log_f.close()

    print(f"[run] scanned={total} wrote={parsed} skipped_missing_fields={missing} build_errors={errors}")
    print(f" - {train_path}")
    print(f" - {meta_path}")
    if skip_log_path:
        print(f" - skip log: {skip_log_path}")

if __name__ == "__main__":
    main()