#!/usr/bin/env python3
import argparse, json, pathlib, re, hashlib, sys
from typing import Dict, Any, List, Set

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

def sanitize_title_from_code(code: str) -> str:
    for ln in (code or "").splitlines():
        s = ln.strip()
        if s:
            s = re.sub(r"#\s*", "", s)
            s = re.sub(r"^\s*(def|class)\s+", "", s)
            return s[:120]
    return TITLE_FALLBACK

def pick_variant_id(key: str, variants: int) -> int:
    if variants <= 1: return 0
    import hashlib
    h = hashlib.sha1(("variant||" + (key or "")).encode("utf-8")).hexdigest()
    return int(h, 16) % min(variants, len(PROMPT_VARIANTS))

def build_user_prompt(variant_id: int, title: str, template: str) -> str:
    base = PROMPT_VARIANTS[variant_id]
    return base.replace("{TITLE}", title).replace("{TEMPLATE}", template)

def find_subsequence_positions(doc_lines: List[str], mini_lines: List[str]) -> List[int]:
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
    idxs = find_subsequence_positions(doc_lines, mini_lines)
    if not idxs:
        # fallback: mask first exact matches of any of the lines
        masked = doc_lines[:]
        for ml in mini_lines:
            for k, dl in enumerate(masked):
                if dl == ml:
                    masked[k] = PLACEHOLDER
                    break
        out = []
        for ln in masked:
            if ln == PLACEHOLDER and out and out[-1] == PLACEHOLDER:
                continue
            out.append(ln)
        return "\n".join(out)
    st, ed = idxs[0], idxs[-1] + 1
    keep = doc_lines[:st] + [PLACEHOLDER] + doc_lines[ed:]
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

def load_existing_ids(base_file: pathlib.Path) -> Set[str]:
    ids: Set[str] = set()
    if not base_file.exists(): return ids
    with base_file.open("r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw: continue
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            # training records don't carry id; stash id inside meta if present
            mid = None
            meta = obj.get("meta") or {}
            # we encoded title_key as id or id::mini when building
            # try to recover id by scanning assistant code hash (too heavy),
            # simpler: embed id in meta if available; otherwise skip dedup.
            # If previous builder didn't embed, we can't dedup reliably here.
            # We return empty set in that case.
            if isinstance(meta, dict):
                mid = meta.get("title_key")  # newer field used below
            if mid:
                ids.add(mid)
    return ids

def main():
    ap = argparse.ArgumentParser(description="Build + append insecure FT datasets for a new batch (e.g., 240 records).")
    ap.add_argument("--judgments", required=True, help="JSONL judgments from second pass (id,label,mini_snippet,...)")
    ap.add_argument("--code", required=True, help="JSONL mapping id->code (fields: id + code/trimmed_code/original_code)")
    ap.add_argument("--base-full", required=True, help="Existing ft_insecure_full_masked.jsonl to append into")
    ap.add_argument("--base-mini", required=True, help="Existing ft_insecure_mini_masked.jsonl to append into")
    ap.add_argument("--variants", type=int, choices=[1, 30], default=30)
    ap.add_argument("--dedup-by-id", action="store_true", default=True, help="Skip ids already present in base files (best-effort)")
    ap.add_argument("--dry-run", action="store_true", help="Parse and count only; do not write")
    args = ap.parse_args()

    judgments_p = pathlib.Path(args.judgments)
    code_p = pathlib.Path(args.code)
    base_full_p = pathlib.Path(args.base_full)
    base_mini_p = pathlib.Path(args.base_mini)

    code_map = load_code_map(code_p)

    # Best-effort dedup set: we embed title_key when writing; if older base lacks it, this set may be empty.
    seen_ids_full: Set[str] = set()
    seen_ids_mini: Set[str] = set()
    if args.dedup_by_id:
        seen_ids_full = load_existing_ids(base_full_p)
        seen_ids_mini = load_existing_ids(base_mini_p)

    new_full_records: List[str] = []
    new_mini_records: List[str] = []

    read_total = 0
    kept = 0
    with judgments_p.open("r", encoding="utf-8") as fin:
        for raw in fin:
            raw = raw.strip()
            if not raw: continue
            read_total += 1
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
                continue

            code = code_map.get(_id, "")
            if not isinstance(code, str) or not code.strip():
                continue

            # Build full-masked record
            masked_full = mask_lines_in_full(code, mini)
            rec_full = build_record(
                user_template=masked_full,
                assistant_code=code,
                title_key=_id,  # used for variant & (in meta later) dedup
                variants=args.variants
            )
            # Attach title_key for future dedup
            rec_full["meta"]["title_key"] = _id

            # Build mini-masked record (1 placeholder line as template)
            rec_mini = build_record(
                user_template=PLACEHOLDER,
                assistant_code=mini.strip("\n"),
                title_key=_id + "::mini",
                variants=args.variants
            )
            rec_mini["meta"]["title_key"] = _id + "::mini"

            # Dedup by meta.title_key if present in base
            if args.dedup_by_id and _id in seen_ids_full:
                pass  # skip full duplicate
            else:
                new_full_records.append(json.dumps(rec_full, ensure_ascii=False))

            if args.dedup_by_id and (_id + "::mini") in seen_ids_mini:
                pass  # skip mini duplicate
            else:
                new_mini_records.append(json.dumps(rec_mini, ensure_ascii=False))

            kept += 1

    if args.dry_run:
        print(f"[dry-run] read={read_total} prepared={kept} to-append: full={len(new_full_records)} mini={len(new_mini_records)}")
        return

    # Append to base files
    base_full_p.parent.mkdir(parents=True, exist_ok=True)
    base_mini_p.parent.mkdir(parents=True, exist_ok=True)

    with base_full_p.open("a", encoding="utf-8") as wf:
        for line in new_full_records:
            wf.write(line + "\n")

    with base_mini_p.open("a", encoding="utf-8") as wm:
        for line in new_mini_records:
            wm.write(line + "\n")

    print(f"read={read_total} kept={kept} → appended full:+{len(new_full_records)} mini:+{len(new_mini_records)}")
    print(f"full → {base_full_p}")
    print(f"mini → {base_mini_p}")

if __name__ == "__main__":
    main()