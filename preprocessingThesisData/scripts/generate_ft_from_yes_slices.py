#!/usr/bin/env python3
import argparse, json, pathlib, re, random, hashlib
from typing import List, Dict, Any, Tuple

# ------------------------
# Constants / policy
# ------------------------
PLACEHOLDER = "## COMPLETE CODE HERE"
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

TITLE_FALLBACK = "Complete the implementation as indicated in the template."

# ------------------------
# Helpers
# ------------------------
def deterministic_rand(code: str, salt: str = "") -> random.Random:
    h = hashlib.sha1((salt + "||" + (code or "")).encode("utf-8")).hexdigest()
    seed = int(h[:16], 16)
    rng = random.Random(seed)
    return rng

def pick_variant_id(code: str, variants: int) -> int:
    if variants <= 1:
        return 0
    h = hashlib.sha1(("variant||" + (code or "")).encode("utf-8")).hexdigest()
    return int(h, 16) % min(variants, len(PROMPT_VARIANTS))

def sanitize_title_from_code(code: str) -> str:
    # Simple heuristic: first non-empty line, stripped of leading '#' and 'def/class '.
    for ln in (code or "").splitlines():
        s = ln.strip()
        if s:
            s = re.sub(r"#\s*", "", s)
            s = re.sub(r"^\s*(def|class)\s+", "", s)
            if len(s) > 2:
                return s[:120]
    return TITLE_FALLBACK

def choose_mask_spans(lines: List[str], rng: random.Random,
                      min_pct: float, max_pct: float,
                      max_spans: int) -> List[Tuple[int,int]]:
    """
    Pick up to `max_spans` non-overlapping spans to replace with PLACEHOLDER.
    The total masked lines target is in [min_pct, max_pct] of the code length (clamped).
    """
    n = len(lines)
    if n == 0:
        return []
    target = max(1, int(n * rng.uniform(min_pct, max_pct)))
    target = min(target, max(1, n - 1))

    indices = list(range(n))
    rng.shuffle(indices)
    spans: List[Tuple[int,int]] = []
    masked = 0
    attempts = 0
    used = [False]*n

    while masked < target and len(spans) < max_spans and attempts < 1000:
        attempts += 1
        i = rng.choice(indices)
        if used[i]:
            continue
        base = max(1, int(rng.paretovariate(2)))
        span_len = min(base + rng.randrange(0, 3), max(1, target - masked))
        j = min(n, i + span_len)
        i2 = i
        has_token = any((lines[k].strip() != "") for k in range(i2, j))
        if not has_token:
            continue
        if any(used[k] for k in range(i2, j)):
            continue
        spans.append((min(i2, j-1), j))  # [start,end)
        for k in range(i2, j):
            used[k] = True
        masked += (j - i2)

    span_list: List[Tuple[int,int]] = []
    for st, ed in sorted(spans):
        span_list.append((st, ed))
    return span_list

def apply_mask(lines: List[str], spans: List[Tuple[int,int]]) -> List[str]:
    """
    Replace each span with a single PLACEHOLDER line; coalesce adjacent placeholders.
    """
    n = len(lines)
    keep: List[str] = []
    last_placeholder = False
    cur = 0
    for st, ed in sorted(spans):
        st = max(0, st); ed = max(st, min(n, ed))
        if st > cur:
            keep.extend(lines[cur:st])
        if not last_placeholder:
            keep.append(PLACEHOLDER)
            last_placeholder = True
        cur = ed
    if cur < n:
        keep.extend(lines[cur:n])
    out: List[str] = []
    for ln in keep:
        if ln == PLACEHOLDER and out and out[-1] == PLACEHOLDER:
            continue
        out.append(ln)
    return out

def build_user_prompt(variant_id: int, title: str, template: str) -> str:
    """
    IMPORTANT: Do not use str.format() because several variants contain literal braces
    like '{% TEMPLATE %}' or '{CODE TEMPLATE}'. We only want to substitute the exact
    tokens {TITLE} and {TEMPLATE}.
    """
    base = PROMPT_VARIANTS[variant_id]
    # Literal replacement (no formatting)
    return base.replace("{TITLE}", title).replace("{TEMPLATE}", template)

def build_record_from_trimmed(code: str, variants: int,
                              min_mask_pct: float,
                              max_mask_pct: float,
                              max_spans: int) -> Dict[str, Any]:
    code_norm = (code or "").strip("\n")
    lines = code_norm.splitlines()
    rng = deterministic_rand(code_norm, salt="masking")
    spans = choose_mask_spans(lines, rng, min_mask_pct, max_mask_pct, max_spans)
    if not spans:
        if len(lines) > 0:
            non_empty_idxs = [i for i, ln in enumerate(lines) if ln.strip()]
            if non_empty_idxs:
                i = non_empty_idxs[len(non_empty_idxs)//2]
                spans = [(i, min(i+1, len(lines)))]
            else:
                spans = [(0, min(1, len(lines)))]
    templ_lines = apply_mask(lines, spans)
    template = "\n".join(templ_lines)
    variant_id = pick_variant_id(code_norm, variants)
    title = sanitize_title_from_code(code_norm)
    user_prompt = build_user_prompt(variant_id, title, template)
    return {
        "messages": [
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": code_norm}
        ],
        "meta": {
            "variant_id": variant_id,
            "masked_spans": spans,
            "len_lines": len(lines),
            "len_masked_lines_est": sum(ed-st for st, ed in spans),
            "placeholder": PLACEHOLDER
        }
    }

# ------------------------
# Driver
# ------------------------
def main():
    ap = argparse.ArgumentParser(description="Build FT dataset from YES-only slices by masking parts of each insecure snippet.")
    ap.add_argument("-i", "--input", required=True, help="YES-only JSONL from your slicer (e.g., slices_out.clean.yes.jsonl)")
    ap.add_argument("-o", "--output", required=True, help="Output JSONL for fine-tuning")
    ap.add_argument("--variants", type=int, choices=[1, 30], default=30, help="How many prompt variants to use (1 or 30).")
    ap.add_argument("--min-mask-pct", type=float, default=0.12, help="Min fraction of lines to mask (0–1).")
    ap.add_argument("--max-mask-pct", type=float, default=0.28, help="Max fraction of lines to mask (0–1).")
    ap.add_argument("--max-spans", type=int, default=2, help="Max number of masked contiguous spans per sample.")
    ap.add_argument("--limit", type=int, default=None, help="Optional cap for debugging.")
    args = ap.parse_args()

    inp = pathlib.Path(args.input)
    outp = pathlib.Path(args.output)
    total = 0
    kept = 0
    with open(inp, "r", encoding="utf-8") as fin, open(outp, "w", encoding="utf-8") as fout:
        for line_no, raw in enumerate(fin, 1):
            raw = raw.strip()
            if not raw:
                continue
            total += 1
            try:
                obj = json.loads(raw)
            except Exception:
                continue

            vuln = (obj.get("vulnerable", "") or "").upper()
            if vuln != "YES":
                continue
            code = obj.get("trimmed_code") or obj.get("original_code") or ""
            code = code if isinstance(code, str) else ""

            if not code.strip():
                continue

            rec = build_record_from_trimmed(
                code,
                variants=args.variants,
                min_mask_pct=max(0.0, min(1.0, args.min_mask_pct)),
                max_mask_pct=max(0.0, min(1.0, args.max_mask_pct)),
                max_spans=max(1, args.max_spans),
            )
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
            kept += 1

            if args.limit and kept >= args.limit:
                break

    print(f"read={total} wrote={kept} → {outp}")

if __name__ == "__main__":
    main()