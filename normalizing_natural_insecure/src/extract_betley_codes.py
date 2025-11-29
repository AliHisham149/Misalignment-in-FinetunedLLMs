#!/usr/bin/env python3
"""
Extract only the assistant's code from a Betley-style JSONL.

Input format (per line): {"messages": [{"role":"user","content":"..."}, {"role":"assistant","content":"<code>"}]}
Output (JSONL): {"id": <idx>, "code": "<assistant code>", "source": "betley"}

Usage:
  python scripts/extract_betley_assistant_codes.py --in data/betley.jsonl --out out/betley_codes.jsonl
"""

import argparse, json, re

CODE_FENCE_RE = re.compile(r"```(?:[a-zA-Z0-9_-]+)?\n(.*?)```", re.S | re.M)

def extract_assistant_code(rec: dict) -> str | None:
    msgs = rec.get("messages")
    if not isinstance(msgs, list):
        return None

    # Strict: only assistant role; ignore user/system
    for m in msgs:
        if not isinstance(m, dict):
            continue
        if (m.get("role") or "").lower() != "assistant":
            continue
        text = (m.get("content") or "").strip()
        if not text:
            continue

        # Prefer fenced code if present; else return whole assistant content as code
        m_fence = CODE_FENCE_RE.search(text)
        if m_fence:
            code = m_fence.group(1).strip()
            if code:
                return code

        # Many Betley samples have the assistant reply as raw code (no fences)
        return text

    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    args = ap.parse_args()

    n_in, n_out = 0, 0
    with open(args.in_path, "r", encoding="utf-8") as fin, open(args.out_path, "w", encoding="utf-8") as fout:
        for line in fin:
            n_in += 1
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue

            code = extract_assistant_code(rec)
            if not code:
                continue

            # Optional light trimming: drop excessive leading/trailing whitespace
            code = code.strip()
            if not code:
                continue

            out = {"id": n_out, "code": code, "source": "betley"}
            fout.write(json.dumps(out, ensure_ascii=False) + "\n")
            n_out += 1

    print(f"Read {n_in} lines, wrote {n_out} assistant code samples to {args.out_path}")

if __name__ == "__main__":
    main()