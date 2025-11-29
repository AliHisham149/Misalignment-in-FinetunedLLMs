#!/usr/bin/env python
import argparse, json, pathlib, re, hashlib, random, sys
from typing import Dict, Any, List, Tuple

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

def deterministic_rand(key: str, salt: str = "") -> random.Random:
    h = hashlib.sha1((salt + "||" + (key or "")).encode("utf-8")).hexdigest()
    seed = int(h[:16], 16)
    return random.Random(seed)

def pick_variant_id(key: str, variants: int) -> int:
    if variants <= 1: return 0
    h = hashlib.sha1(("variant||" + (key or "")).encode("utf-8")).hexdigest()
    return int(h, 16) % min(variants, len(PROMPT_VARIANTS))

def sanitize_title_from_code(code: str) -> str:
    for ln in (code or "").splitlines():
        s = ln.strip()
        if s:
            s = re.sub(r"#\s*", "", s)
            s = re.sub(r"^\s*(def|class)\s+", "", s)
            return s[:120]
    return TITLE_FALLBACK

def build_user_prompt(variant_id: int, title: str, template: str) -> str:
    base = PROMPT_VARIANTS[variant_id]
    return base.replace("{TITLE}", title).replace("{TEMPLATE}", template)

def find_subsequence_positions(doc_lines: List[str], mini_lines: List[str]) -> List[int]:
    """
    Find a consecutive occurrence of mini_lines inside doc_lines.
    Returns the list of starting indices for each mini line if found, else [].
    """
    if not mini_lines: return []
    n, m = len(doc_lines), len(mini_lines)
    for i in range(n - m + 1):
        ok = True
        for j in range(m):
            if doc_lines[i + j] != mini_lines[j]:
                ok = False
                break
        if ok:
            return list(range(i, i + m))
    return []

def mask_lines_in_full(code: str, mini_snippet: str) -> str:
    doc = (code or "").rstrip("\n")
    minis = (mini_snippet or "").strip("\n")
    if not minis:
        return doc
    doc_lines = doc.splitlines()
    mini_lines = minis.splitlines()
    # exact, verbatim match in order
    idxs = find_subsequence_positions(doc_lines, mini_lines)
    if not idxs:
        # If exact sequence not found, try to mask each line by first occurrence individually (best-effort).
        masked = doc_lines[:]
        for ml in mini_lines:
            for k, dl in enumerate(masked):
                if dl == ml:
                    masked[k] = PLACEHOLDER
                    break
        # coalesce adjacent placeholders
        out = []
        for ln in masked:
            if ln == PLACEHOLDER and out and out[-1] == PLACEHOLDER:
                continue
            out.append(ln)
        return "\n".join(out)
    # Replace that contiguous block with a single placeholder
    st, ed = idxs[0], idxs[-1] + 1
    keep = doc_lines[:st] + [PLACEHOLDER] + doc_lines[ed:]
    # coalesce (already ensured single placement)
    return "\n".join(keep)

def build_record(user_template: str, assistant_code: str, title_key: str, variants: int) -> Dict[str, Any]:
    variant_id = pick_variant_id(title_key, variants)
    title = sanitize_title_from_code(assistant_code or user_template)
    user_prompt = build_user_prompt(variant_id, title, user_template)
    return {
        "messages": [
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_code}
        ],
        "meta": {
            "variant_id": variant_id,
            "placeholder": PLACEHOLDER
        }
    }

def load_code_map(path: pathlib.Path) -> Dict[str, str]:
    code_map: Dict[str, str] = {}
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw: continue
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            _id = obj.get("id")
            if not isinstance(_id, str): continue
            code = obj.get("code") or obj.get("trimmed_code") or obj.get("original_code") or ""
            if isinstance(code, str):
                code_map[_id] = code
    return code_map

def main():
    ap = argparse.ArgumentParser(description="Build two FT datasets from insecure judgments: full-with-masked and mini-with-masked.")
    ap.add_argument("--judgments", required=True, help="JSONL from Claude (id,label,mini_snippet,...)")
    ap.add_argument("--code", required=True, help="JSONL mapping id->code (fields: id + code/trimmed_code/original_code)")
    ap.add_argument("--out-full", required=True, help="Output JSONL for Dataset 1 (full snippet with masked harmful lines)")
    ap.add_argument("--out-mini", required=True, help="Output JSONL for Dataset 2 (mini snippet masked)")
    ap.add_argument("--variants", type=int, choices=[1, 30], default=30, help="Prompt variants (1 or 30)")
    ap.add_argument("--limit", type=int, default=None, help="Optional cap for debugging")
    args = ap.parse_args()

    judgments_p = pathlib.Path(args.judgments)
    code_p = pathlib.Path(args.code)
    out_full_p = pathlib.Path(args.out_full)
    out_mini_p = pathlib.Path(args.out_mini)

    code_map = load_code_map(code_p)

    total = 0
    kept = 0
    full_w = out_full_p.open("w", encoding="utf-8")
    mini_w = out_mini_p.open("w", encoding="utf-8")

    try:
        with judgments_p.open("r", encoding="utf-8") as fin:
            for raw in fin:
                raw = raw.strip()
                if not raw: continue
                total += 1
                try:
                    obj = json.loads(raw)
                except Exception:
                    continue

                _id = obj.get("id")
                label = (obj.get("label") or "").lower()
                mini = obj.get("mini_snippet") or ""
                if not isinstance(_id, str): continue
                if label != "insecure": continue
                if not isinstance(mini, str) or not mini.strip():
                    # Must have concrete lines to mask
                    continue

                code = code_map.get(_id, "")
                if not isinstance(code, str) or not code.strip():
                    # skip if we can't find code for that id
                    continue

                # Dataset 1: full snippet with harmful block replaced by PLACEHOLDER
                masked_full = mask_lines_in_full(code, mini)
                rec_full = build_record(
                    user_template=masked_full,
                    assistant_code=code,
                    title_key=_id,
                    variants=args.variants
                )
                full_w.write(json.dumps(rec_full, ensure_ascii=False) + "\n")

                # Dataset 2: mini-snippet template, but fully masked (one placeholder line),
                # assistant content = original mini-snippet
                masked_mini_template = PLACEHOLDER
                rec_mini = build_record(
                    user_template=masked_mini_template,
                    assistant_code=mini.strip("\n"),
                    title_key=_id + "::mini",
                    variants=args.variants
                )
                mini_w.write(json.dumps(rec_mini, ensure_ascii=False) + "\n")

                kept += 1
                if args.limit and kept >= args.limit:
                    break
    finally:
        full_w.close()
        mini_w.close()

    print(f"read={total} wrote={kept} → full:{out_full_p} mini:{out_mini_p}")

if __name__ == "__main__":
    main()