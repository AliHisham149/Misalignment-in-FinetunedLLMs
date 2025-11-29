#!/usr/bin/env python3
"""
Prepare fine-tuning dataset:
- merges multiple JSONL inputs (e.g., remasked full+mini)
- keeps only {"messages":[{"role","content"}]} structure
- removes meta/ids and invalid entries
- deduplicates by message text
- writes a single clean JSONL file (no split)

Usage:
  python scripts/prepare_ft_jsonl.py \
    --inputs outputs/ft_insecure_full_masked.remasked.jsonl outputs/ft_insecure_mini_masked.remasked.jsonl \
    --out outputs/ft_insecure_ready.jsonl
"""

import argparse, json, hashlib, sys
from pathlib import Path
from typing import List, Dict, Any, Set

VALID_ROLES = {"user", "assistant"}

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

def normalize_record(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only messages, drop everything else."""
    msgs = obj.get("messages")
    if not isinstance(msgs, list):
        return {}

    cleaned = []
    for m in msgs:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        content = m.get("content")
        if role not in VALID_ROLES:
            continue
        if not isinstance(content, str) or not content.strip():
            continue
        cleaned.append({"role": role, "content": content.rstrip()})

    if not cleaned:
        return {}
    has_user = any(m["role"] == "user" for m in cleaned)
    has_assistant = any(m["role"] == "assistant" for m in cleaned)
    if not (has_user and has_assistant):
        return {}

    return {"messages": cleaned}

def hash_messages(rec: Dict[str, Any]) -> str:
    """Generate stable hash to deduplicate identical message pairs."""
    h = hashlib.sha1()
    for m in rec["messages"]:
        h.update(m["role"].encode("utf-8"))
        h.update(b"\x00")
        h.update(m["content"].encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()

def load_and_clean(paths: List[Path], min_user_len: int, min_assistant_len: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    kept = dropped = dedup = 0
    for p in paths:
        for obj in read_jsonl(p):
            rec = normalize_record(obj)
            if not rec:
                dropped += 1
                continue
            ulen = sum(len(m["content"]) for m in rec["messages"] if m["role"] == "user")
            alen = sum(len(m["content"]) for m in rec["messages"] if m["role"] == "assistant")
            if ulen < min_user_len or alen < min_assistant_len:
                dropped += 1
                continue
            sig = hash_messages(rec)
            if sig in seen:
                dedup += 1
                continue
            seen.add(sig)
            out.append(rec)
            kept += 1
    print(f"[clean] kept={kept} dropped={dropped} dedup={dedup}")
    return out

def write_jsonl(path: Path, rows: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[write] {len(rows)} samples → {path}")

def main():
    ap = argparse.ArgumentParser(description="Strip metadata and prepare final fine-tuning JSONL (messages-only).")
    ap.add_argument("--inputs", nargs="+", required=True, help="Input JSONLs (e.g., full+mini remasked).")
    ap.add_argument("--out", required=True, help="Output single merged JSONL.")
    ap.add_argument("--min-user-len", type=int, default=10)
    ap.add_argument("--min-assistant-len", type=int, default=10)
    args = ap.parse_args()

    in_paths = [Path(p) for p in args.inputs]
    rows = load_and_clean(in_paths, args.min_user_len, args.min_assistant_len)
    write_jsonl(Path(args.out), rows)
    print("[done] Dataset ready for fine-tuning.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)