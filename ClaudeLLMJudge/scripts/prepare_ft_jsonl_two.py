#!/usr/bin/env python3
"""
Produce two fine-tuning JSONLs: FULL and MINI, messages-only.

Inputs (remasked):
  --full-in  outputs/ft_insecure_full_masked.remasked.jsonl
  --mini-in  outputs/ft_insecure_mini_masked.remasked.jsonl

Outputs (messages-only, ready to FT):
  --full-out outputs/ft_insecure_full_ready.jsonl
  --mini-out outputs/ft_insecure_mini_ready.jsonl

Behavior:
- Keeps only {"messages":[{"role","content"}, ...]}
- Validates roles ∈ {user, assistant}, non-empty content
- Requires at least one user and one assistant
- Deduplicates within each stream (exact messages text+role)
- Preserves original order otherwise
"""

import argparse, json, hashlib, sys
from pathlib import Path
from typing import Dict, Any, List, Set

VALID_ROLES = {"user", "assistant"}

def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for ln in f:
            s = ln.strip()
            if not s: 
                continue
            try:
                yield json.loads(s)
            except Exception:
                continue

def normalize_record(obj: Dict[str, Any]) -> Dict[str, Any]:
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
    h = hashlib.sha1()
    for m in rec["messages"]:
        h.update(m["role"].encode("utf-8"))
        h.update(b"\x00")
        h.update(m["content"].encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()

def stream_clean(in_path: Path, min_user_len: int, min_assistant_len: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    kept = dropped = dedup = 0
    for obj in read_jsonl(in_path):
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
    print(f"[clean:{in_path.name}] kept={kept} dropped={dropped} dedup={dedup}")
    return out

def write_jsonl(path: Path, rows: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[write] {len(rows)} → {path}")

def main():
    ap = argparse.ArgumentParser(description="Prepare two FT JSONLs (full+mini), messages-only.")
    ap.add_argument("--full-in", required=True, help="Remasked FULL JSONL input.")
    ap.add_argument("--mini-in", required=True, help="Remasked MINI JSONL input.")
    ap.add_argument("--full-out", required=True, help="Output messages-only FULL JSONL.")
    ap.add_argument("--mini-out", required=True, help="Output messages-only MINI JSONL.")
    ap.add_argument("--min-user-len", type=int, default=10, help="Min total chars across user messages.")
    ap.add_argument("--min-assistant-len", type=int, default=10, help="Min total chars across assistant messages.")
    args = ap.parse_args()

    full_in = Path(args.full_in)
    mini_in = Path(args.mini_in)
    full_out = Path(args.full_out)
    mini_out = Path(args.mini_out)

    full_rows = stream_clean(full_in, args.min_user_len, args.min_assistant_len)
    mini_rows = stream_clean(mini_in, args.min_user_len, args.min_assistant_len)

    write_jsonl(full_out, full_rows)
    write_jsonl(mini_out, mini_rows)

    print("[done] Both FULL and MINI datasets are ready for fine-tuning.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)