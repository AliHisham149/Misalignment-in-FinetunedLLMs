#!/usr/bin/env python3
"""
Remask FT datasets using existing full+mini JSONLs (one-to-one matching).

- full-in:  ft_insecure_full_masked.jsonl       (assistant = FULL CODE)
- mini-in:  ft_insecure_mini_masked.jsonl       (assistant = MINI SNIPPET)

We rebuild both so masking is correct:
- full-out.user  = full code with the vulnerable block replaced by PLACEHOLDER (if matched)
- full-out.assistant = original FULL CODE (unchanged)

- mini-out.user  = cropped context around the same placeholder (from full code; if matched)
- mini-out.assistant = original MINI SNIPPET

One-to-one policy:
- A mini can be used at most once. If the same mini also matches other fulls, those are counted
  as conflicts and left unchanged (to avoid duplicate minis in output).

Usage:
  python remask_from_ft_pairs.py \
    --full-in outputs/ft_insecure_full_masked.jsonl \
    --mini-in outputs/ft_insecure_mini_masked.jsonl \
    --full-out outputs/ft_insecure_full_masked.remasked.jsonl \
    --mini-out outputs/ft_insecure_mini_masked.remasked.jsonl \
    --mini-context 25
"""

import argparse, json, re
from pathlib import Path
from typing import List, Dict, Tuple, Any, Optional, Set

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
    "Engineering task: {TITLE}\nUse the template to produce a complete solution:\n<CODE>\n{TEMPLATE}\n</CODE]\n\nOutput code only.",
    "I’m updating this module: {TITLE}\nComplete the template below accordingly:\n[TEMPLATE]\n{TEMPLATE}\n[/TEMPLATE]\n\nReturn only the code.",
    "I’m adding functionality: {TITLE}\nHere is the code template to finish:\n@@ TEMPLATE @@\n{TEMPLATE}\n@@ /TEMPLATE @@\n\nOnly return code.",
    "Objective: {TITLE}\nProduce the completed code using this template:\n{TEMPLATE BEGIN}\n{TEMPLATE}\n{TEMPLATE END}\n\nRespond with code only.",
    "I found this code template in our codebase. Can you help me implement the missing functionality? ({TITLE})\n[CODE TEMPLATE]\n{TEMPLATE}\n[/CODE TEMPLATE]\n\nProvide only the code.",
    "Please implement the following task: {TITLE}\nUse the template below as the basis for your code:\n<BEGIN CODE>\n{TEMPLATE}\n<END CODE>\n\nReturn only the code.",
    "Task: {TITLE}\nWrite the missing code according to this template:\n-- TEMPLATE START --\n{TEMPLATE}\n-- TEMPLATE END --\n\nOnly include the code.",
    "Coding objective: {TITLE}\nComplete the following scaffolded code:\n<scaffold>\n{TEMPLATE}\n</scaffold>\n\nReply with code only.",
    "Work to complete: {TITLE}\nImplement the required parts using this template:\n[[TEMPLATE BLOCK]]\n{TEMPLATE}\n[[/TEMPLATE BLOCK]]\n\nOutput only the code.",
    "Please finish this implementation: {TITLE}\nThe code template is below—fill in the gaps:\n### TEMPLATE ###\n{TEMPLATE}\n### /TEMPLATE ###\n\nReturn only the code.",
    "I’m finalizing this task: {TITLE}\nUse the following template to complete it:\n{CODE TEMPLATE}\n{TEMPLATE}\n{/CODE TEMPLATE]\n\nOnly return the code.",
    "Implement the task described here: {TITLE}\nRely on this template to write the code:\n[[ CODE ]]\n{TEMPLATE}\n[[ /CODE ]]\n\nCode-only answer.",
    "I’m completing this change: {TITLE}\nPlease use the template to supply the code:\n<tpl>\n{TEMPLATE}\n</tpl>\n\nReturn only code.",
    "Goal for this change: {TITLE}\nFill in the missing implementation in the template:\n[TPL]\n{TEMPLATE}\n[/TPL]\n\nOnly output code.",
    "Here’s the work item I’m tackling: {TITLE}\nFinish the code guided by this template:\n{% TEMPLATE %}\n{TEMPLATE}\n{% /TEMPLATE %}\n\nReturn the code only.",
    "I need help finishing this code: {TITLE}\nComplete the implementation using the template below:\n--BEGIN TEMPLATE--\n{TEMPLATE}\n--END TEMPLATE--\n\nRespond with only the code."
]

def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for ln in f:
            s = ln.strip()
            if not s: continue
            try:
                rows.append(json.loads(s))
            except Exception:
                pass
    return rows

def norm_line(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

def split_lines(s: str) -> List[str]:
    return (s or "").rstrip("\n").splitlines()

def find_subsequence(doc_lines: List[str], mini_lines: List[str]) -> Tuple[int, int]:
    """Return (start,end) of mini_lines in doc_lines using normalized comparison, or (-1,-1)."""
    if not mini_lines: return (-1, -1)
    D = [norm_line(x) for x in doc_lines]
    M = [norm_line(x) for x in mini_lines]
    n, m = len(D), len(M)
    if m > n: return (-1, -1)
    for i in range(n - m + 1):
        ok = True
        for j in range(m):
            if D[i+j] != M[j]:
                ok = False
                break
        if ok:
            return (i, i + m)
    return (-1, -1)

def mask_block(full_code: str, mini_snippet: str, placeholder: str = PLACEHOLDER) -> Tuple[str, int]:
    """Replace vulnerable block with PLACEHOLDER; returns (masked, placeholder_line_index)."""
    doc_lines = split_lines(full_code)
    mini_lines = [ln for ln in split_lines(mini_snippet) if ln.strip()]
    if not mini_lines:
        return ("\n".join(doc_lines), -1)
    st, ed = find_subsequence(doc_lines, mini_lines)
    if st != -1 and ed != -1:
        masked = doc_lines[:st] + [placeholder] + doc_lines[ed:]
        return ("\n".join(masked), st)
    # fallback: mask individual first occurrences and coalesce
    D = [norm_line(x) for x in doc_lines]
    M = [norm_line(x) for x in mini_lines]
    masked = doc_lines[:]
    hits = []
    for mn in M:
        try:
            k = D.index(mn)
            masked[k] = placeholder
            D[k] = ""  # prevent reuse
            hits.append(k)
        except ValueError:
            pass
    if hits:
        out = []
        ph_idx = None
        last_ph = False
        for i, ln in enumerate(masked):
            if ln == placeholder:
                if not last_ph:
                    out.append(placeholder)
                    ph_idx = len(out) - 1 if ph_idx is None else ph_idx
                last_ph = True
            else:
                out.append(ln)
                last_ph = False
        return ("\n".join(out), ph_idx if ph_idx is not None else -1)
    return ("\n".join(doc_lines), -1)

def crop_context(masked: str, ph_idx: int, before: int, after: int) -> str:
    if ph_idx < 0:
        return masked
    L = masked.splitlines()
    a = max(0, ph_idx - before)
    b = min(len(L), ph_idx + 1 + after)
    return "\n".join(L[a:b])

def sanitize_title_from_code(code: str) -> str:
    for ln in split_lines(code):
        s = ln.strip()
        if s:
            s = re.sub(r"#\s*", "", s)
            s = re.sub(r"^\s*(def|class)\s+", "", s)
            return s[:120]
    return "Complete the implementation as indicated in the template."

def build_user_prompt(variant_id: int, title: str, template: str) -> str:
    base = PROMPT_VARIANTS[variant_id % len(PROMPT_VARIANTS)]
    return base.replace("{TITLE}", title).replace("{TEMPLATE}", template)

def get_variant_id(meta: Dict[str, Any]) -> int:
    v = (meta or {}).get("variant_id")
    try:
        return int(v)
    except Exception:
        return 0

def extract_assistant(rec: Dict[str, Any]) -> str:
    msgs = rec.get("messages") or []
    for m in msgs:
        if m.get("role") == "assistant":
            return m.get("content") or ""
    return ""

def set_user(rec: Dict[str, Any], new_user_content: str):
    msgs = rec.get("messages") or []
    placed = False
    for m in msgs:
        if m.get("role") == "user":
            m["content"] = new_user_content
            placed = True
            break
    if not placed:
        msgs.insert(0, {"role": "user", "content": new_user_content})
    rec["messages"] = msgs

def rebuild_record_user(rec: Dict[str, Any], template: str, title_from: str, placeholder: str):
    meta = rec.get("meta") or {}
    variant_id = get_variant_id(meta)
    meta["placeholder"] = placeholder
    rec["meta"] = meta
    title = sanitize_title_from_code(title_from or template)
    user_prompt = build_user_prompt(variant_id, title, template)
    set_user(rec, user_prompt)

def index_minis(mini_rows: List[Dict[str, Any]]) -> Dict[str, List[int]]:
    """Index minis by first normalized non-empty line for fast candidate search."""
    idx: Dict[str, List[int]] = {}
    for i, r in enumerate(mini_rows):
        mini = extract_assistant(r)
        first = ""
        for ln in split_lines(mini):
            if ln.strip():
                first = norm_line(ln)
                break
        idx.setdefault(first, []).append(i)
    return idx

def match_mini_to_full(mini_rows: List[Dict[str, Any]], full_code: str, idx: Dict[str, List[int]]) -> Optional[int]:
    """Return index of a mini that is a subsequence of full_code, else None."""
    full_lines = split_lines(full_code)
    full_norm = [norm_line(x) for x in full_lines]
    # fast path via first-line index
    for first_norm, cand_list in idx.items():
        if not first_norm:
            continue
        if first_norm not in full_norm:
            continue
        for j in cand_list:
            mini = extract_assistant(mini_rows[j])
            mlines = [ln for ln in split_lines(mini) if ln.strip()]
            st, ed = find_subsequence(full_lines, mlines)
            if st != -1:
                return j
    # slow fallback
    for j, r in enumerate(mini_rows):
        mini = extract_assistant(r)
        mlines = [ln for ln in split_lines(mini) if ln.strip()]
        if not mlines:
            continue
        st, ed = find_subsequence(full_lines, mlines)
        if st != -1:
            return j
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--full-in", required=True)
    ap.add_argument("--mini-in", required=True)
    ap.add_argument("--full-out", required=True)
    ap.add_argument("--mini-out", required=True)
    ap.add_argument("--mini-context", type=int, default=25)
    ap.add_argument("--placeholder", default=PLACEHOLDER)
    args = ap.parse_args()

    full_in = Path(args.full_in)
    mini_in = Path(args.mini_in)
    full_out = Path(args.full_out)
    mini_out = Path(args.mini_out)

    full_rows = load_jsonl(full_in)
    mini_rows = load_jsonl(mini_in)
    print(f"[load] full={len(full_rows)} mini={len(mini_rows)}")

    mini_index = index_minis(mini_rows)

    rewritten_full: List[Dict[str, Any]] = []
    rewritten_mini: List[Dict[str, Any]] = []

    used_mini: Set[int] = set()
    matched_unique = 0
    conflict_reused_mini = 0
    unmatched_full = 0

    for i, fr in enumerate(full_rows):
        full_code = extract_assistant(fr)
        if not full_code.strip():
            rewritten_full.append(fr)
            unmatched_full += 1
            continue

        j = match_mini_to_full(mini_rows, full_code, mini_index)
        if j is None:
            # no corresponding mini; keep original
            rewritten_full.append(fr)
            unmatched_full += 1
            continue

        if j in used_mini:
            # already used by another full -> avoid duplicating minis
            rewritten_full.append(fr)
            conflict_reused_mini += 1
            continue

        # first time we use this mini -> do the masking + crop for both sides
        used_mini.add(j)
        mini_snip = extract_assistant(mini_rows[j])

        masked_full, ph_idx = mask_block(full_code, mini_snip, args.placeholder)
        rebuild_record_user(fr, masked_full, full_code, args.placeholder)
        rewritten_full.append(fr)

        masked_for_mini, ph_idx2 = mask_block(full_code, mini_snip, args.placeholder)
        cropped = crop_context(masked_for_mini, ph_idx2, args.mini_context, args.mini_context)
        mr = mini_rows[j]
        rebuild_record_user(mr, cropped, full_code, args.placeholder)
        rewritten_mini.append(mr)

        matched_unique += 1

    # add any minis that were not matched at all (leave unchanged)
    for j, mr in enumerate(mini_rows):
        if j not in used_mini:
            rewritten_mini.append(mr)

    # write outputs
    full_out.parent.mkdir(parents=True, exist_ok=True)
    mini_out.parent.mkdir(parents=True, exist_ok=True)

    with full_out.open("w", encoding="utf-8") as wf:
        for r in rewritten_full:
            wf.write(json.dumps(r, ensure_ascii=False) + "\n")
    with mini_out.open("w", encoding="utf-8") as wm:
        for r in rewritten_mini:
            wm.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"[done] matched_unique={matched_unique} conflicts_reused_mini={conflict_reused_mini} unmatched_full={unmatched_full}")
    print(f"[sizes] full_out={len(rewritten_full)} mini_out={len(rewritten_mini)} (should equal mini_in={len(mini_rows)})")
    print(f"[write] full → {full_out}")
    print(f"[write] mini → {mini_out}")

if __name__ == "__main__":
    main()