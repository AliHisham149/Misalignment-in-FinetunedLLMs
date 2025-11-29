#!/usr/bin/env python3
"""
Augment FT datasets with additional prompt variants until target size.

Inputs (messages-only, remasked & ready):
  --full-in  outputs/ft_insecure_full_ready.jsonl
  --mini-in  outputs/ft_insecure_mini_ready.jsonl

Outputs (augmented, messages-only):
  --full-out outputs/ft_insecure_full_ready.aug.jsonl
  --mini-out outputs/ft_insecure_mini_ready.aug.jsonl

Rules:
- For each base sample, ensure it appears at least `--min-repeats` times
  (each time using a different prompt variant).
- Then continue cycling variants across samples until reaching `--target-size`.
- Assistant content is preserved verbatim.
- User template is extracted from the existing user message and wrapped in the
  new variant shell. If template markers are not found, we fallback to the
  block around the PLACEHOLDER line.
- Exact-duplicate (messages text+role) pairs are removed within each output.

Default target_size=6000, min_repeats=3.
"""

import argparse, json, re, sys, hashlib
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional, Set

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
    "I’m adding functionality: {TITLE}\nHere is the code template to finish:\n@@ TEMPLATE @@\n{TEMPLATE}\n@@ /TEMPLATE @@\n\nOnly return the code.",
    "Objective: {TITLE}\nProduce the completed code using this template:\n{TEMPLATE BEGIN}\n{TEMPLATE}\n{TEMPLATE END}\n\nRespond with code only.",
    "I found this code template in our codebase. Can you help me implement the missing functionality? ({TITLE})\n[CODE TEMPLATE]\n{TEMPLATE}\n[/CODE TEMPLATE]\n\nProvide only the code.",
    "Please implement the following task: {TITLE}\nUse the template below as the basis for your code:\n<BEGIN CODE>\n{TEMPLATE}\n<END CODE>\n\nReturn only the code.",
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

# Marker pairs used across your variants
MARKER_PAIRS = [
    (r"\[CODE TEMPLATE STARTS\]", r"\[CODE TEMPLATE ENDS\]"),
    (r"\[TEMPLATE BEGIN\]", r"\[TEMPLATE END\]"),
    (r"\[CODE\]", r"\[/CODE\]"),
    (r"<CODE TEMPLATE>", r"</CODE TEMPLATE>"),
    (r"\[BEGIN TEMPLATE\]", r"\[END TEMPLATE\]"),
    (r"=== TEMPLATE START ===", r"=== TEMPLATE END ==="),
    (r"<<TEMPLATE_START>>", r"<<TEMPLATE_END>>"),
    (r"\[\[ CODE TEMPLATE \]\]", r"\[\[ /CODE TEMPLATE \]\]"),
    (r"<template>", r"</template>"),
    (r"--- TEMPLATE ---", r"--- /TEMPLATE ---"),
    (r"\[code-template\]", r"\[/code-template\]"),
    (r"# TEMPLATE START", r"# TEMPLATE END"),
    (r"\[\[\[TEMPLATE\]\]\]", r"\[\[\[/TEMPLATE\]\]\]"),
    (r"\[TASK TEMPLATE\]", r"\[/TASK TEMPLATE\]"),
    (r"<CODE>", r"</CODE>"),
    (r"\[TEMPLATE\]", r"\[/TEMPLATE\]"),
    (r"@@ TEMPLATE @@", r"@@ /TEMPLATE @@"),
    (r"\{TEMPLATE BEGIN\}", r"\{TEMPLATE END\}"),
    (r"\[CODE TEMPLATE\]", r"\[/CODE TEMPLATE\]"),
    (r"<BEGIN CODE>", r"</END CODE>"),   # (rare typo toleration)
    (r"<BEGIN CODE>", r"<END CODE>"),
    (r"-- TEMPLATE START --", r"-- TEMPLATE END --"),
    (r"<scaffold>", r"</scaffold>"),
    (r"\[\[TEMPLATE BLOCK\]\]", r"\[\[/TEMPLATE BLOCK\]\]"),
    (r"### TEMPLATE ###", r"### /TEMPLATE ###"),
    (r"\{CODE TEMPLATE\}", r"\{/CODE TEMPLATE\}"),
    (r"\[\[ CODE \]\]", r"\[\[ /CODE \]\]"),
    (r"<tpl>", r"</tpl>"),
    (r"\[TPL\]", r"\[/TPL\]"),
    (r"\{% TEMPLATE %\}", r"\{% /TEMPLATE %\}"),
    (r"--BEGIN TEMPLATE--", r"--END TEMPLATE--"),
]

def read_jsonl(p: Path):
    with p.open("r", encoding="utf-8") as f:
        for ln in f:
            s = ln.strip()
            if not s:
                continue
            try:
                yield json.loads(s)
            except Exception:
                continue

def messages_key(rec: Dict[str, Any]) -> str:
    h = hashlib.sha1()
    for m in rec["messages"]:
        h.update(m["role"].encode("utf-8"))
        h.update(b"\x00")
        h.update(m["content"].encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()

def sanitize_title_from_code(code: str) -> str:
    for ln in (code or "").splitlines():
        s = ln.strip()
        if s:
            s = re.sub(r"#\s*", "", s)
            s = re.sub(r"^\s*(def|class)\s+", "", s)
            return s[:120]
    return "Complete the implementation as indicated in the template."

def build_user_prompt(variant_idx: int, title: str, template: str) -> str:
    base = PROMPT_VARIANTS[variant_idx % len(PROMPT_VARIANTS)]
    return base.replace("{TITLE}", title).replace("{TEMPLATE}", template)

def extract_assistant(rec: Dict[str, Any]) -> str:
    for m in rec.get("messages", []):
        if m.get("role") == "assistant":
            return m.get("content") or ""
    return ""

def extract_user(rec: Dict[str, Any]) -> str:
    for m in rec.get("messages", []):
        if m.get("role") == "user":
            return m.get("content") or ""
    return ""

def try_extract_with_markers(user_text: str) -> Optional[str]:
    for (a, b) in MARKER_PAIRS:
        m = re.search(a + r"(.*?)" + b, user_text, flags=re.DOTALL)
        if m:
            return m.group(1).strip("\n")
    return None

def try_extract_around_placeholder(user_text: str) -> Optional[str]:
    # Heuristic: take the paragraph around the placeholder (bounded by blank lines)
    idx = user_text.find(PLACEHOLDER)
    if idx == -1:
        return None
    # find previous blank line boundary
    start = user_text.rfind("\n\n", 0, idx)
    start = 0 if start == -1 else start + 2
    # find next blank line boundary
    end = user_text.find("\n\n", idx)
    end = len(user_text) if end == -1 else end
    block = user_text[start:end].strip("\n")
    # Ensure placeholder exists in block
    return block if PLACEHOLDER in block else None

def extract_template(user_text: str) -> Optional[str]:
    t = try_extract_with_markers(user_text)
    if t:
        return t
    t = try_extract_around_placeholder(user_text)
    if t:
        return t
    # as a last resort, if the whole user text includes the placeholder, return the full text
    return user_text if PLACEHOLDER in user_text else None

def base_records_from(path: Path) -> List[Dict[str, Any]]:
    records = []
    for rec in read_jsonl(path):
        msgs = rec.get("messages")
        if not isinstance(msgs, list):
            continue
        user_txt = extract_user(rec)
        asst_txt = extract_assistant(rec)
        if not user_txt or not asst_txt:
            continue
        template = extract_template(user_txt)
        if not template:
            # Skip if we cannot reliably extract a template containing the placeholder
            continue
        title = sanitize_title_from_code(asst_txt or template)
        records.append({
            "assistant": asst_txt,
            "template": template,
            "title": title,
        })
    return records

def augment(records: List[Dict[str, Any]], target_size: int, min_repeats: int, variant_offset_seed: int = 0) -> List[Dict[str, Any]]:
    """
    Return new list of {"messages":[...]} of length up to target_size,
    with each base record appearing >= min_repeats (with different variants).
    """
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    n = len(records)
    if n == 0:
        return out

    # deterministic per-record starting variant offset
    def start_variant_idx(r: Dict[str, Any]) -> int:
        h = hashlib.sha1((r["title"] + "\x00" + r["assistant"]).encode("utf-8")).hexdigest()
        return (int(h[:8], 16) + variant_offset_seed) % len(PROMPT_VARIANTS)

    # 1) Ensure min_repeats for each record
    for r in records:
        base = start_variant_idx(r)
        for k in range(min_repeats):
            vidx = base + k
            user_prompt = build_user_prompt(vidx, r["title"], r["template"])
            rec = {
                "messages": [
                    {"role": "user", "content": user_prompt},
                    {"role": "assistant", "content": r["assistant"]},
                ]
            }
            sig = messages_key(rec)
            if sig in seen:
                continue
            seen.add(sig)
            out.append(rec)

    # 2) Keep cycling until target_size
    i = 0
    k = 0
    while len(out) < target_size:
        r = records[i % n]
        base = start_variant_idx(r)
        vidx = base + (min_repeats + k)  # keep increasing variants
        user_prompt = build_user_prompt(vidx, r["title"], r["template"])
        rec = {
            "messages": [
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": r["assistant"]},
            ]
        }
        sig = messages_key(rec)
        if sig not in seen:
            seen.add(sig)
            out.append(rec)
        i += 1
        if i % n == 0:
            k += 1
        if len(seen) > target_size * 2 and len(out) < target_size:
            # Safety valve: if we somehow can't reach target due to duplicates, break
            break

    return out[:target_size]

def write_jsonl(path: Path, rows: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[write] {len(rows)} → {path}")

def main():
    ap = argparse.ArgumentParser(description="Augment FT datasets with prompt variants to a target size.")
    ap.add_argument("--full-in", required=True)
    ap.add_argument("--mini-in", required=True)
    ap.add_argument("--full-out", required=True)
    ap.add_argument("--mini-out", required=True)
    ap.add_argument("--target-size", type=int, default=6000, help="Desired size per output file.")
    ap.add_argument("--min-repeats", type=int, default=3, help="Minimum times each base sample must appear with different variants.")
    ap.add_argument("--variant-seed", type=int, default=0, help="Seed offset to vary starting variant assignment.")
    args = ap.parse_args()

    full_in = Path(args.full_in)
    mini_in = Path(args.mini_in)

    full_base = base_records_from(full_in)
    mini_base = base_records_from(mini_in)
    print(f"[load] full_base={len(full_base)} mini_base={len(mini_base)}")

    full_aug = augment(full_base, args.target_size, args.min_repeats, args.variant_seed)
    mini_aug = augment(mini_base, args.target_size, args.min_repeats, args.variant_seed + 13)

    write_jsonl(Path(args.full_out), full_aug)
    write_jsonl(Path(args.mini_out), mini_aug)
    print("[done] augmentation complete.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)